import os
from sqlalchemy import create_engine, Table, Column, Integer, String, Float, MetaData
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

class DBLogger:
    def __init__(self):
        self.db_url = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@" \
                      f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
        print("Connecting to:", self.db_url)
        self.engine = create_engine(self.db_url)
        self.metadata = MetaData()
        self.trades = Table('trades', self.metadata,
                            Column('id', Integer, primary_key=True),
                            Column('symbol', String),
                            Column('side', String),
                            Column('amount', Float),
                            Column('price', Float)
                            )
        self.metadata.create_all(self.engine)

    def log_trade(self, symbol, side, amount, price):
        try:
            Session = sessionmaker(bind=self.engine)
            with Session() as session:
                insert_stmt = self.trades.insert().values(
                    symbol=symbol,
                    side=side,
                    amount=amount,
                    price=price
                )
                session.execute(insert_stmt)
                session.commit()
                print(f"Logged trade: {side} {symbol} at {price}")
        except SQLAlchemyError as e:
            print(f"DB logging error: {e}")




