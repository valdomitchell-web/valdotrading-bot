import time

class EMARsiStrategy:
    def __init__(self, client):
        self.client = client

    def run(self, db_logger):
        print("Running EMA + RSI strategy...")
        # Simulated logic
        db_logger.log_trade("BTC/USDT", "BUY", 1, 50000)
        time.sleep(1)
        db_logger.log_trade("BTC/USDT", "SELL", 1, 51000)
