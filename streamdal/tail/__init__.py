import logging
import asyncio
import streamdal_protos.protos as protos
import time
from streamdal.metrics import Metrics, CounterEntry, COUNTER_DROPPED_TAIL_MESSAGES
from grpclib.client import Channel
from grpclib.exceptions import ProtocolError
from queue import SimpleQueue, Empty
from threading import Lock, Event, Thread

# The number of tail worker threads to start
NUM_TAIL_WORKERS = 2
MIN_TAIL_RESPONSE_INTERVAL = 10_000_000  # 10ms


class Tail:
    request: protos.TailRequest
    auth_token: str
    streamdal_url: str
    metrics: Metrics
    lock: Lock = Lock()
    exit: Event = Event()
    queue: SimpleQueue = SimpleQueue()
    last_msg: int = 0
    log: logging.Logger = logging.getLogger("streamdal-python-sdk")

    def __init__(
        self,
        request: protos.TailRequest,
        streamdal_url: str,
        exit: Event,
        auth_token: str,
        log: logging.Logger,
        metrics: Metrics,
    ):
        self.request = request
        self.queue = SimpleQueue()
        self.exit = exit
        self.log = log
        self.auth_token = auth_token
        self.streamdal_url = streamdal_url
        self.metrics = metrics

    def tail_iterator(self):
        while not self.exit.is_set():
            try:
                yield self.queue.get(timeout=1)
            except Empty:
                pass

            self.last_msg = time.time_ns()

    def start_tail_workers(self):
        for i in range(NUM_TAIL_WORKERS):
            incr_worker = Thread(
                target=self.start_tail_worker, args=(i + 1,), daemon=False
            )
            incr_worker.start()

    def start_tail_worker(self, worker_id: int):
        self.log.debug(f"Starting tail worker {worker_id}")

        # Create gRPC channel and stub
        (host, port) = self.streamdal_url.split(":")
        loop = asyncio.new_event_loop()
        channel = Channel(host=host, port=port, loop=loop)
        stub = protos.InternalStub(channel=channel)

        async def call():
            try:
                # If we're sending too fast, drop the message
                if time.time_ns() - self.last_msg < MIN_TAIL_RESPONSE_INTERVAL:
                    self.metrics.incr(
                        CounterEntry(
                            name=COUNTER_DROPPED_TAIL_MESSAGES,
                            value=1.0,
                            labels={},
                            aud=self.request.audience,
                        )
                    )

                    self.log.warning(
                        f"Dropping tail response for {self.request.id}, too fast"
                    )

                await stub.send_tail(
                    tail_response_iterator=self.tail_iterator(),
                    metadata={"auth-token": self.auth_token},
                )
            except AssertionError:
                # Ignore. This will occur on server disconnect since the gRPC
                # library is expecting a response
                pass
            except ProtocolError:
                pass

        while not self.exit.is_set():
            loop.run_until_complete(call())

        channel.close()

        self.log.debug(f"Tail worker {worker_id} exiting")