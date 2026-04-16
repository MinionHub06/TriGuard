# test_redis.py
import redis

r = redis.from_url("redis://localhost:6379")

# Test 1: Basic ping
print("Ping:", r.ping())               # True

# Test 2: Set and get a value
r.set("triguard_test", "connected")
print("Get:", r.get("triguard_test"))  # b'connected'

# Test 3: Simulate behavioral layer key
r.zadd("triguard:ip:127.0.0.1", {"req1": 1.0})
print("ZCard:", r.zcard("triguard:ip:127.0.0.1"))  # 1

# Test 4: TTL and expiry
r.expire("triguard:ip:127.0.0.1", 60)
print("TTL:", r.ttl("triguard:ip:127.0.0.1"))      # 60 (or close)

# Cleanup
r.delete("triguard_test", "triguard:ip:127.0.0.1")
print("\n✅ Redis connection fully verified for TriGuard v2")