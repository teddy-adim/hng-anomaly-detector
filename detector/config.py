import yaml
import os


def load_config(path="/app/config.yaml"):
    with open(path, "r") as f:
        config = yaml.safe_load(f)

    # Override slack webhook from environment variable
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    if slack_webhook:
        config["slack"]["webhook_url"] = slack_webhook

    return config
