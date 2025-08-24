from strategies.ema_rsi_strategy import EMARsiStrategy
from utils.db_logger import DBLogger
from utils.telegram import send_telegram_message
from utils.exchange import get_binance_client
from dotenv import load_dotenv
import os

load_dotenv()

if __name__ == "__main__":
    client = get_binance_client(paper=True)
    strategy = EMARsiStrategy(client)
    db_logger = DBLogger()
    strategy.run(db_logger)
