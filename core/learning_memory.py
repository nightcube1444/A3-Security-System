"""
A3 Security System — Learning Memory

Stores lessons learned from:
- failed experiments
- false positives
- successful fixes
- weak detection rules
- model weaknesses

This is the beginning of A3's self-learning memory.
"""

import json
from pathlib import Path
from datetime import datetime
from uuid import uuid4


BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
MEMORY_PATH = DATA_DIR / "learning_memory.json"

DATA_DIR.mkdir(exist_ok=True)


class LearningMemory:

    def __init__(self):
        self._init_memory()

    def _init_memory(self):
        if not MEMORY_PATH.exists():
            with open(MEMORY_PATH, "w") as f:
                json.dump([], f, indent=2)

    def load(self):
        with open(MEMORY_PATH, "r") as f:
            return json.load(f)

    def save(self, memories):
        with open(MEMORY_PATH, "w") as f:
            json.dump(memories, f, indent=2)

    def add_lesson(
        self,
        title,
        category,
        problem,
        cause,
        fix,
        result="PENDING",
        confidence=0.5,
        tags=None,
    ):
        memories = self.load()

        lesson = {
            "id": f"LESSON-{uuid4().hex[:8].upper()}",
            "timestamp": datetime.now().isoformat(),
            "title": title,
            "category": category,
            "problem": problem,
            "cause": cause,
            "fix": fix,
            "result": result,
            "confidence": confidence,
            "tags": tags or [],
        }

        memories.append(lesson)
        self.save(memories)

        return lesson

    def list_lessons(self, limit=10):
        memories = self.load()
        return memories[-limit:]

    def find_by_tag(self, tag):
        memories = self.load()
        return [
            m for m in memories
            if tag in m.get("tags", [])
        ]

    def summarize(self):
        memories = self.load()

        summary = {
            "total_lessons": len(memories),
            "categories": {},
            "pending": 0,
            "successful": 0,
            "failed": 0,
        }

        for m in memories:
            category = m.get("category", "unknown")
            summary["categories"][category] = summary["categories"].get(category, 0) + 1

            result = m.get("result", "").upper()

            if result == "PENDING":
                summary["pending"] += 1
            elif result in ["SUCCESS", "IMPROVED", "FIXED"]:
                summary["successful"] += 1
            elif result in ["FAILED", "REGRESSION"]:
                summary["failed"] += 1

        return summary


if __name__ == "__main__":
    memory = LearningMemory()

    lesson = memory.add_lesson(
        title="Socket detection threshold was too low",
        category="experiment_failure",
        problem="suspicious_socket.py was expected to be SUSPICIOUS but A3 marked it CLEAN.",
        cause="The socket rule scored only 25 points, below the suspicious threshold of 30.",
        fix="Increase socket detection score from 25 to 30.",
        result="FIXED",
        confidence=0.9,
        tags=["experiment", "socket", "false_negative", "detection_rule"]
    )

    print("\nSaved lesson:")
    print(json.dumps(lesson, indent=2))

    print("\nMemory summary:")
    print(json.dumps(memory.summarize(), indent=2))