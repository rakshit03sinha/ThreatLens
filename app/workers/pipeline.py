"""ThreatLens Ingestion Worker Pipeline."""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


class IngestionWorkerQueue:
    """In-process asynchronous job worker with concurrency control and bounded retries.

    Limitations:
    - In-process memory queue: tasks pending in memory will be lost if the process restarts.
    - Designed with an abstract enqueue interface to facilitate swap with durable brokers (e.g. RabbitMQ, Redis, Kafka).
    """

    def __init__(self, concurrency: int = 4, max_retries: int = 3):
        self.concurrency = concurrency
        self.max_retries = max_retries
        self._queue: asyncio.Queue = asyncio.Queue()
        self._workers: list[asyncio.Task] = []
        self._running = False

    async def start(self):
        """Start worker consumer tasks."""
        if self._running:
            return
        self._running = True
        for i in range(self.concurrency):
            t = asyncio.create_task(self._worker_loop(i))
            self._workers.append(t)
        logger.info(f"Started {self.concurrency} IngestionWorkerQueue background workers.")

    async def stop(self):
        """Gracefully stop background workers."""
        self._running = False
        for t in self._workers:
            t.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("IngestionWorkerQueue background workers stopped.")

    async def enqueue(self, task_func: Callable, *args, **kwargs) -> bool:
        """Enqueue an async task for background processing."""
        await self._queue.put((task_func, args, kwargs, 0))
        return True

    async def _worker_loop(self, worker_id: int):
        while self._running:
            try:
                task_func, args, kwargs, attempt = await self._queue.get()
                try:
                    await task_func(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    logger.error(
                        f"Worker {worker_id}: task {task_func.__name__} failed (attempt {attempt}/{self.max_retries}): {str(e)}",
                        exc_info=True,
                    )
                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * (2 ** attempt))  # exponential backoff
                        await self._queue.put((task_func, args, kwargs, attempt))
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} unexpected error: {str(e)}", exc_info=True)


worker_queue = IngestionWorkerQueue(
    concurrency=settings.WORKER_CONCURRENCY,
    max_retries=settings.MAX_INGESTION_RETRIES,
)
