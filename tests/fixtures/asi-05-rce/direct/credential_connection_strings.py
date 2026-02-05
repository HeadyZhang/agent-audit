"""
Vuln: hardcoded DB connection strings.
Expected: AGENT-004.
"""
MONGO_URI = "mongodb://admin:secretpass@mongo.internal:27017/agentdb"  # LINE 5
REDIS_URL = "redis://:mypassword@redis.internal:6379/0"  # LINE 6
MYSQL_DSN = "mysql://root:hunter2@mysql.internal:3306/agents"  # LINE 7
