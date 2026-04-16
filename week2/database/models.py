from datetime import datetime
from extensions import db


class AttackLog(db.Model):
    __tablename__ = 'attack_logs'

    id               = db.Column(db.Integer, primary_key=True)
    timestamp        = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address       = db.Column(db.String(50))
    payload          = db.Column(db.Text)
    ml_score         = db.Column(db.Float)
    ast_score        = db.Column(db.Float)
    behavioral_score = db.Column(db.Float)
    final_score      = db.Column(db.Float, index=True)
    risk_level       = db.Column(db.String(10), index=True)
    top_features     = db.Column(db.Text)   # JSON string

    def to_dict(self):
        return {
            "id":           self.id,
            "timestamp":    self.timestamp.isoformat(),
            "ip":           self.ip_address,
            "payload":      self.payload,
            "ml_score":     round(self.ml_score or 0, 4),
            "ast_score":    round(self.ast_score or 0, 4),
            "behavioral":   round(self.behavioral_score or 0, 4),
            "final_score":  round(self.final_score or 0, 4),
            "risk_level":   self.risk_level,
            "top_features": self.top_features,
        }