from services.model_service import train_and_save
if __name__ == "__main__":
    metrics = train_and_save()["metrics"]
    print(f"Model trained on {metrics['samples']} pattern examples")
    print(f"Pattern holdout accuracy: {metrics['holdout_accuracy']:.3f}")
    print(metrics["note"])

