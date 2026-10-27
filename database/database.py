
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = PROJECT_ROOT / "database" / "scamshield.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                urls_found TEXT NOT NULL DEFAULT '[]',
                explanations TEXT NOT NULL DEFAULT '[]',
                safety_recommendations TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def save_analysis(
    message,
    prediction,
    confidence,
    urls_found,
    explanations,
    safety_recommendations,
):
    import json

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analysis_history (
                message,
                prediction,
                confidence,
                urls_found,
                explanations,
                safety_recommendations
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message,
                prediction,
                confidence,
                json.dumps(urls_found, ensure_ascii=False),
                json.dumps(explanations, ensure_ascii=False),
                json.dumps(
                    safety_recommendations,
                    ensure_ascii=False,
                ),
            ),
        )

        return cursor.lastrowid


def get_history(limit=50):
    import json

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    results = []

    for row in rows:
        item = dict(row)
        item["urls_found"] = json.loads(item["urls_found"])
        item["explanations"] = json.loads(item["explanations"])
        item["safety_recommendations"] = json.loads(
            item["safety_recommendations"]
        )
        results.append(item)

    return results
