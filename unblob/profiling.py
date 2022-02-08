import json
import os
import threading
import time
from collections import defaultdict
from typing import cast

import attr

from unblob.report import Report


def get_thread_description():
    pid = os.getpid()
    current_thread = threading.current_thread()
    tid = current_thread.native_id
    tname = current_thread.name
    return f'Process {pid} Thread {tid} "{tname}"'


@attr.define(kw_only=True)
class OpenEvent(Report):
    tag: str
    path: str
    thread_description: str = attr.field(factory=get_thread_description)
    timestamp: int = attr.field(factory=time.perf_counter_ns)


@attr.define(kw_only=True)
class CloseEvent(Report):
    open_event: OpenEvent
    thread_description: str = attr.field(factory=get_thread_description)
    timestamp: int = attr.field(factory=time.perf_counter_ns)


class PerfCounter:
    def __init__(self, result, tag, **meta):
        self.open_event = None
        self.result = result
        if meta:
            kvpairs = ",".join(f"{k}={v!r}" for k, v in meta.items())
            self.tag = f"{tag} [{kvpairs}]"
        else:
            self.tag = tag

    def __enter__(self):
        self.open_event = OpenEvent(tag=self.tag, path=str(self.result.task.path))

    def __exit__(self, _exc_type, _exc_value, _tb):
        self.result.add_report(self.open_event)
        self.result.add_report(CloseEvent(open_event=cast(OpenEvent, self.open_event)))


def to_speedscope(report, fd):
    # Speedscope's file format specification:
    #   https://github.com/jlfwong/speedscope/wiki/Importing-from-custom-sources#speedscopes-file-format
    frames = []
    events = defaultdict(list)

    frame_stack = {}

    type_map = {OpenEvent: "O", CloseEvent: "C"}

    perf_events = [e for e in report if isinstance(e, (OpenEvent, CloseEvent))]
    perf_events = sorted(perf_events, key=lambda e: e.timestamp)
    start = perf_events[0].timestamp
    end = perf_events[-1].timestamp

    for entry in perf_events:
        if isinstance(entry, OpenEvent):
            frame_index = len(frames)
            frame_stack[entry] = frame_index
            frame = {
                "name": entry.tag,
                "file": entry.path,
            }
            frames.append(frame)
        else:
            frame_index = frame_stack.pop(entry.open_event)
        thread = entry.thread_description
        event = {
            "type": type_map[type(entry)],
            "frame": frame_index,
            "at": entry.timestamp,
        }

        events[thread].append(event)

    profiles = [
        {
            "type": "evented",
            "name": name,
            "unit": "nanoseconds",
            "startValue": start,
            "endValue": end,
            "events": events,
        }
        for name, events in events.items()
    ]

    speedscope = {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "shared": {"frames": frames},
        "profiles": profiles,
    }
    json.dump(speedscope, fd, indent=4)
