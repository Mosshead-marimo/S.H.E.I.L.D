from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from db.database import Base

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    ml_score = Column(Float)
    nlp_score = Column(Float)
    cv_score = Column(Float)
    risk_score = Column(Float)
    verdict = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    
class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer)
    is_phishing = Column(Integer)  # 1 = phishing, 0 = legit
    comment = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserAccount(Base):
    __tablename__ = "user_accounts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)


class TrustedSender(Base):
    __tablename__ = "trusted_senders"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, index=True, nullable=False)  # email/phone/domain
    type = Column(String, nullable=False)  # email/phone/domain
    scope = Column(String, nullable=False, default="admin")  # admin/user
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockedEntity(Base):
    __tablename__ = "blocked_entities"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, index=True, nullable=False)  # email/phone/domain/url
    type = Column(String, nullable=False)  # email/phone/domain/url
    scope = Column(String, nullable=False, default="admin")  # admin/user
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockEvent(Base):
    __tablename__ = "block_events"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer)
    reason = Column(String, nullable=True)
    source = Column(String, nullable=True)  # sender/url/domain/keyword
    created_at = Column(DateTime, default=datetime.utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
