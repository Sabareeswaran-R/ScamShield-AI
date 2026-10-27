
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = PROJECT_ROOT / "data" / "raw" / "scam_messages.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "scam_classifier.joblib"


def main():
    print("Loading scam detection dataset...")

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    # Validate dataset
    required_columns = {"message", "label"}

    if not required_columns.issubset(df.columns):
        raise ValueError(
            "CSV must contain 'message' and 'label' columns."
        )

    df = df.dropna(subset=["message", "label"])
    df["message"] = df["message"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    df = df[df["message"] != ""]

    allowed_labels = {"scam", "legitimate"}

    if not set(df["label"].unique()).issubset(allowed_labels):
        raise ValueError(
            "Labels must be 'scam' or 'legitimate'."
        )

    if df["label"].nunique() != 2 or df["label"].value_counts().min() < 2:
        raise ValueError(
            "Dataset must contain at least two examples per class."
        )

    X = df["message"]
    y = df["label"]

    print(f"Dataset size: {len(df)} messages")
    print("\nSplitting data into training and testing sets...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    # Build the machine learning pipeline
    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                strip_accents="unicode",
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    print("Training the machine learning model...")
    model.fit(X_train, y_train)

    # Evaluate the model
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print("\n--- Model Evaluation ---")
    print(f"Test accuracy: {accuracy:.2%}")
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["legitimate", "scam"],
            zero_division=0,
        )
    )

    # Save trained model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"\nModel saved successfully:\n{MODEL_PATH}")
    print("\nTraining completed!")


if __name__ == "__main__":
    main()
