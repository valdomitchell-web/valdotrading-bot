# models.py
from sqlalchemy import Column, Integer, String, Boolean, JSON
from database import Base

class BotState(Base):
    __tablename__ = "bot_state"

    id = Column(Integer, primary_key=True, index=True)
    trading_paused = Column(Boolean, default=False)
    daily_profit_target = Column(Integer, nullable=True)  # store in cents or %
    notes = Column(String, nullable=True)

class TrailingCfg(Base):
    __tablename__ = "trailing_cfgs"

    id = Column(Integer, primary_key=True, index=True)
    symbol = Column(String, unique=True, index=True)
    config = Column(JSON)   # stores your trailing config as JSON
    active = Column(Boolean, default=True)
