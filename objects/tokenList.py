
import threading
import time
import json
import base64

import redis

from common.ripple import userUtils
from common.log import logUtils as log
from common.sentry import sentry
from constants import serverPackets
from constants.exceptions import periodicLoopException
from events import logoutEvent
from objects import glob
from objects import osuToken


class tokenList:
	def __init__(self):
		# Keep a local cache for performance, but primary storage is Redis
		self._tokenCache = {}
		self._lock = threading.Lock()
		
	def _getTokenKey(self, token):
		"""Get Redis key for token storage"""
		return f"peppy:tokens:{token}"
	
	def _getUserTokensKey(self, userID):
		"""Get Redis key for user->tokens mapping"""
		return f"peppy:user_tokens:{userID}"
	
	def _getUsernameTokensKey(self, username):
		"""Get Redis key for username->tokens mapping"""
		return f"peppy:username_tokens:{username.lower()}"
	
	def _serializeToken(self, tokenObj):
		"""Serialize token object to JSON for Redis storage"""
		try:
			# Convert bytes queue to base64 for JSON serialization
			queueB64 = base64.b64encode(tokenObj.queue).decode('utf-8') if tokenObj.queue else ""
			
			# Safely convert values with proper defaults
			data = {
				'userID': int(tokenObj.userID if tokenObj.userID is not None else 0),
				'username': str(tokenObj.username if tokenObj.username is not None else ""),
				'safeUsername': str(tokenObj.safeUsername if tokenObj.safeUsername is not None else ""),
				'privileges': int(tokenObj.privileges if tokenObj.privileges is not None else 0),
				'admin': bool(tokenObj.admin if tokenObj.admin is not None else False),
				'irc': bool(tokenObj.irc if tokenObj.irc is not None else False),
				'kicked': bool(tokenObj.kicked if tokenObj.kicked is not None else False),
				'restricted': bool(tokenObj.restricted if tokenObj.restricted is not None else False),
				'loginTime': int(tokenObj.loginTime if tokenObj.loginTime is not None else 0),
				'pingTime': int(tokenObj.pingTime if tokenObj.pingTime is not None else 0),
				'timeOffset': int(tokenObj.timeOffset if tokenObj.timeOffset is not None else 0),
				'streams': list(tokenObj.streams) if tokenObj.streams else [],
				'tournament': bool(tokenObj.tournament if tokenObj.tournament is not None else False),
				'messagesBuffer': list(tokenObj.messagesBuffer) if tokenObj.messagesBuffer else [],
				'spectators': list(tokenObj.spectators) if tokenObj.spectators else [],
				'spectating': str(tokenObj.spectating) if tokenObj.spectating else None,
				'spectatingUserID': int(tokenObj.spectatingUserID if tokenObj.spectatingUserID is not None else 0),
				'location': list(tokenObj.location) if tokenObj.location else [0, 0],
				'joinedChannels': list(tokenObj.joinedChannels) if tokenObj.joinedChannels else [],
				'ip': str(tokenObj.ip if tokenObj.ip is not None else ""),
				'country': int(tokenObj.country if tokenObj.country is not None else 0),
				'awayMessage': str(tokenObj.awayMessage if tokenObj.awayMessage is not None else ""),
				'sentAway': list(tokenObj.sentAway) if tokenObj.sentAway else [],
				'matchID': int(tokenObj.matchID if tokenObj.matchID is not None else -1),
				'tillerino': list(tokenObj.tillerino) if tokenObj.tillerino else [0, 0, -1.0],
				'silenceEndTime': int(tokenObj.silenceEndTime if tokenObj.silenceEndTime is not None else 0),
				'queue': queueB64,
				'spamRate': int(tokenObj.spamRate if tokenObj.spamRate is not None else 0),
				'actionID': int(tokenObj.actionID if tokenObj.actionID is not None else 0),
				'actionText': str(tokenObj.actionText if tokenObj.actionText is not None else ""),
				'actionMd5': str(tokenObj.actionMd5 if tokenObj.actionMd5 is not None else ""),
				'actionMods': int(tokenObj.actionMods if tokenObj.actionMods is not None else 0),
				'gameMode': int(tokenObj.gameMode if tokenObj.gameMode is not None else 0),
				'beatmapID': int(tokenObj.beatmapID if tokenObj.beatmapID is not None else 0),
				'rankedScore': int(tokenObj.rankedScore if tokenObj.rankedScore is not None else 0),
				'accuracy': float(tokenObj.accuracy if tokenObj.accuracy is not None else 0.0),
				'playcount': int(tokenObj.playcount if tokenObj.playcount is not None else 0),
				'totalScore': int(tokenObj.totalScore if tokenObj.totalScore is not None else 0),
				'gameRank': int(tokenObj.gameRank if tokenObj.gameRank is not None else 0),
				'pp': int(tokenObj.pp if tokenObj.pp is not None else 0),
				'token': str(tokenObj.token if tokenObj.token is not None else "")
			}
			return json.dumps(data, separators=(',', ':'))  # Compact JSON
		except Exception as e:
			log.error(f"Failed to serialize token {getattr(tokenObj, 'token', 'unknown')}: {e}")
			log.error(f"Token object attributes: userID={getattr(tokenObj, 'userID', None)}, username={getattr(tokenObj, 'username', None)}")
			raise
	
	def _deserializeToken(self, jsonData):
		"""Deserialize JSON data back to token object"""
		data = json.loads(jsonData)
		
		# Create token object with basic params
		tokenObj = osuToken.token(
			data['userID'], 
			token_=data['token'],
			ip=data['ip'],
			irc=data['irc'],
			timeOffset=data['timeOffset'],
			tournament=data['tournament']
		)
		
		# Restore all the state
		tokenObj.username = data['username']
		tokenObj.safeUsername = data['safeUsername']
		tokenObj.privileges = data['privileges']
		tokenObj.admin = data['admin']
		tokenObj.kicked = data['kicked']
		tokenObj.restricted = data['restricted']
		tokenObj.loginTime = data['loginTime']
		tokenObj.pingTime = data['pingTime']
		tokenObj.streams = data['streams']
		tokenObj.messagesBuffer = data['messagesBuffer']
		tokenObj.spectators = data['spectators']
		tokenObj.spectating = data['spectating']
		tokenObj.spectatingUserID = data['spectatingUserID']
		tokenObj.location = data['location']
		tokenObj.joinedChannels = data['joinedChannels']
		tokenObj.country = data['country']
		tokenObj.awayMessage = data['awayMessage']
		tokenObj.sentAway = data['sentAway']
		tokenObj.matchID = data['matchID']
		tokenObj.tillerino = data['tillerino']
		tokenObj.silenceEndTime = data['silenceEndTime']
		tokenObj.spamRate = data['spamRate']
		tokenObj.actionID = data['actionID']
		tokenObj.actionText = data['actionText']
		tokenObj.actionMd5 = data['actionMd5']
		tokenObj.actionMods = data['actionMods']
		tokenObj.gameMode = data['gameMode']
		tokenObj.beatmapID = data['beatmapID']
		tokenObj.rankedScore = data['rankedScore']
		tokenObj.accuracy = data['accuracy']
		tokenObj.playcount = data['playcount']
		tokenObj.totalScore = data['totalScore']
		tokenObj.gameRank = data['gameRank']
		tokenObj.pp = data['pp']
		
		# Restore bytes queue from base64
		if data['queue']:
			tokenObj.queue = base64.b64decode(data['queue'].encode('utf-8'))
		else:
			tokenObj.queue = bytes()
		
		# Note: Locks are recreated in the constructor, no need to restore them
		
		return tokenObj
	
	def _saveTokenToRedis(self, tokenObj):
		"""Save token to Redis and update indexes"""
		try:
			tokenKey = self._getTokenKey(tokenObj.token)
			userTokensKey = self._getUserTokensKey(tokenObj.userID)
			usernameTokensKey = self._getUsernameTokensKey(tokenObj.username)
			
			# Serialize and save token 
			serializedToken = self._serializeToken(tokenObj)
			
			# Use set with ex parameter instead of setex for better compatibility
			glob.redis.set(tokenKey, serializedToken, ex=86400)
			
			# Update indexes with TTL
			glob.redis.sadd(userTokensKey, tokenObj.token)
			glob.redis.expire(userTokensKey, 86400)
			glob.redis.sadd(usernameTokensKey, tokenObj.token)
			glob.redis.expire(usernameTokensKey, 86400)
			
			# Update cache
			self._tokenCache[tokenObj.token] = tokenObj
		except Exception as e:
			log.error(f"Failed to save token to Redis for user {getattr(tokenObj, 'username', 'unknown')} (ID: {getattr(tokenObj, 'userID', 'unknown')}): {e}")
			log.error(f"Token: {getattr(tokenObj, 'token', 'unknown')}")
			# Fall back to cache only
			self._tokenCache[tokenObj.token] = tokenObj
	
	def _removeTokenFromRedis(self, token):
		"""Remove token from Redis and update indexes"""
		try:
			tokenKey = self._getTokenKey(token)
			
			# Get token data first to clean up indexes
			tokenData = glob.redis.get(tokenKey)
			if tokenData:
				try:
					data = json.loads(tokenData)
					userTokensKey = self._getUserTokensKey(data['userID'])
					usernameTokensKey = self._getUsernameTokensKey(data['username'])
					
					# Remove from indexes
					glob.redis.srem(userTokensKey, token)
					glob.redis.srem(usernameTokensKey, token)
				except (json.JSONDecodeError, KeyError):
					pass
			
			# Remove token
			glob.redis.delete(tokenKey)
			
			# Remove from cache
			self._tokenCache.pop(token, None)
		except Exception as e:
			log.error(f"Failed to remove token from Redis: {e}")
			# Still remove from cache
			self._tokenCache.pop(token, None)
	
	def _getTokenFromRedis(self, token):
		"""Get token object from Redis"""
		# Check cache first
		if token in self._tokenCache:
			return self._tokenCache[token]
		
		try:
			tokenKey = self._getTokenKey(token)
			tokenData = glob.redis.get(tokenKey)
			
			if tokenData:
				try:
					tokenObj = self._deserializeToken(tokenData)
					# Update cache
					self._tokenCache[token] = tokenObj
					return tokenObj
				except (json.JSONDecodeError, KeyError) as e:
					log.error(f"Failed to deserialize token {token}: {e}")
					return None
		except Exception as e:
			log.error(f"Failed to get token from Redis: {e}")
		
		return None
	
	def _updateTokenInRedis(self, tokenObj):
		"""Update existing token in Redis"""
		self._saveTokenToRedis(tokenObj)

	@property
	def tokens(self):
		"""Provide backward compatibility by returning a dict-like object"""
		class TokenDict:
			def __init__(self, tokenList):
				self.tokenList = tokenList
			
			def __contains__(self, token):
				return self.tokenList._getTokenFromRedis(token) is not None
			
			def __getitem__(self, token):
				tokenObj = self.tokenList._getTokenFromRedis(token)
				if tokenObj is None:
					raise KeyError(token)
				# Return a wrapped token that auto-saves changes
				return TokenWrapper(tokenObj, self.tokenList)
			
			def __setitem__(self, token, tokenObj):
				# If it's a wrapper, get the underlying token
				if isinstance(tokenObj, TokenWrapper):
					tokenObj = tokenObj._tokenObj
				self.tokenList._saveTokenToRedis(tokenObj)
			
			def pop(self, token, default=None):
				tokenObj = self.tokenList._getTokenFromRedis(token)
				if tokenObj:
					self.tokenList._removeTokenFromRedis(token)
					return TokenWrapper(tokenObj, self.tokenList)
				return default
			
			def get(self, token, default=None):
				tokenObj = self.tokenList._getTokenFromRedis(token)
				if tokenObj:
					return TokenWrapper(tokenObj, self.tokenList)
				return default
			
			def items(self):
				# Get all token keys from Redis
				pattern = "peppy:tokens:*"
				keys = glob.redis.keys(pattern)
				for key in keys:
					# Decode key if it's bytes
					key_str = key.decode('utf-8') if isinstance(key, bytes) else key
					token = key_str.split(":")[-1]  # Extract token from key
					tokenObj = self.tokenList._getTokenFromRedis(token)
					if tokenObj:
						yield token, TokenWrapper(tokenObj, self.tokenList)
			
			def keys(self):
				# Get all token keys from Redis
				pattern = "peppy:tokens:*"
				keys = glob.redis.keys(pattern)
				for key in keys:
					# Decode key if it's bytes
					key_str = key.decode('utf-8') if isinstance(key, bytes) else key
					token = key_str.split(":")[-1]  # Extract token from key
					yield token
			
			def values(self):
				# Get all token keys from Redis
				pattern = "peppy:tokens:*"
				keys = glob.redis.keys(pattern)
				for key in keys:
					# Decode key if it's bytes
					key_str = key.decode('utf-8') if isinstance(key, bytes) else key
					token = key_str.split(":")[-1]  # Extract token from key
					tokenObj = self.tokenList._getTokenFromRedis(token)
					if tokenObj:
						yield TokenWrapper(tokenObj, self.tokenList)
		
		return TokenDict(self)

	def __enter__(self):
		self._lock.acquire()

	def __exit__(self, exc_type, exc_val, exc_tb):
		self._lock.release()

	def addToken(self, userID, ip = "", irc = False, timeOffset=0, tournament=False):
		"""
		Add a token object to tokens list

		:param userID: user id associated to that token
		:param ip: ip address of the client
		:param irc: if True, set this token as IRC client
		:param timeOffset: the time offset from UTC for this user. Default: 0.
		:param tournament: if True, flag this client as a tournement client. Default: True.
		:return: token object
		"""
		newToken = osuToken.token(userID, ip=ip, irc=irc, timeOffset=timeOffset, tournament=tournament)
		self._saveTokenToRedis(newToken)
		glob.redis.incr("ripple:online_users")
		return TokenWrapper(newToken, self)

	def deleteToken(self, token):
		"""
		Delete a token from token list if it exists

		:param token: token string
		:return:
		"""
		tokenObj = self._getTokenFromRedis(token)
		if tokenObj:
			if tokenObj.ip != "":
				userUtils.deleteBanchoSessions(tokenObj.userID, tokenObj.ip)
			self._removeTokenFromRedis(token)
			del tokenObj
			glob.redis.decr("ripple:online_users")

	def getUserIDFromToken(self, token):
		"""
		Get user ID from a token

		:param token: token to find
		:return: False if not found, userID if found
		"""
		# Make sure the token exists
		tokenObj = self._getTokenFromRedis(token)
		if not tokenObj:
			return False

		# Get userID associated to that token
		return tokenObj.userID

	def getTokenFromUserID(self, userID, ignoreIRC=False, _all=False):
		"""
		Get token from a user ID

		:param userID: user ID to find
		:param ignoreIRC: if True, consider bancho clients only and skip IRC clients
		:param _all: if True, return a list with all clients that match given username, otherwise return
					only the first occurrence.
		:return: False if not found, token object if found
		"""
		# Make sure the token exists
		ret = []
		userID = int(userID)
		
		# Get tokens for this user from Redis index
		userTokensKey = self._getUserTokensKey(userID)
		tokenStrings = glob.redis.smembers(userTokensKey)
		
		for tokenString in tokenStrings:
			# Decode token string if it's bytes
			token_str = tokenString.decode('utf-8') if isinstance(tokenString, bytes) else tokenString
			tokenObj = self._getTokenFromRedis(token_str)
			if tokenObj and tokenObj.userID == userID:
				if ignoreIRC and tokenObj.irc:
					continue
				wrappedToken = TokenWrapper(tokenObj, self)
				if _all:
					ret.append(wrappedToken)
				else:
					return wrappedToken

		# Return full list or None if not found
		if _all:
			return ret
		else:
			return None

	def getTokenFromUsername(self, username, ignoreIRC=False, safe=False, _all=False):
		"""
		Get an osuToken object from an username

		:param username: normal username or safe username
		:param ignoreIRC: if True, consider bancho clients only and skip IRC clients
		:param safe: 	if True, username is a safe username,
						compare it with token's safe username rather than normal username
		:param _all: if True, return a list with all clients that match given username, otherwise return
					only the first occurrence.
		:return: osuToken object or None
		"""
		# lowercase
		who = username.lower() if not safe else username

		# Make sure the token exists
		ret = []
		
		# Get tokens for this username from Redis index
		usernameTokensKey = self._getUsernameTokensKey(who if not safe else username)
		tokenStrings = glob.redis.smembers(usernameTokensKey)
		
		for tokenString in tokenStrings:
			# Decode token string if it's bytes
			token_str = tokenString.decode('utf-8') if isinstance(tokenString, bytes) else tokenString
			tokenObj = self._getTokenFromRedis(token_str)
			if tokenObj:
				if (not safe and tokenObj.username.lower() == who) or (safe and tokenObj.safeUsername == who):
					if ignoreIRC and tokenObj.irc:
						continue
					wrappedToken = TokenWrapper(tokenObj, self)
					if _all:
						ret.append(wrappedToken)
					else:
						return wrappedToken

		# Return full list or None if not found
		if _all:
			return ret
		else:
			return None

	def deleteOldTokens(self, userID):
		"""
		Delete old userID's tokens if found

		:param userID: tokens associated to this user will be deleted
		:return:
		"""
		# Delete older tokens
		delete = []
		
		# Get all tokens for this user
		userTokensKey = self._getUserTokensKey(userID)
		tokenStrings = glob.redis.smembers(userTokensKey)
		
		for tokenString in tokenStrings:
			# Decode token string if it's bytes
			token_str = tokenString.decode('utf-8') if isinstance(tokenString, bytes) else tokenString
			tokenObj = self._getTokenFromRedis(token_str)
			if tokenObj and tokenObj.userID == userID:
				delete.append(tokenObj)

		for i in delete:
			logoutEvent.handle(i)

	def multipleEnqueue(self, packet, who, but = False):
		"""
		Enqueue a packet to multiple users

		:param packet: packet bytes to enqueue
		:param who: userIDs array
		:param but: if True, enqueue to everyone but users in `who` array
		:return:
		"""
		try:
			# Get all token keys from Redis
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			
			# Use pipeline for better performance
			pipe = glob.redis.pipeline()
			tokens_to_update = []
			
			for key in keys:
				# Decode key if it's bytes
				key_str = key.decode('utf-8') if isinstance(key, bytes) else key
				token = key_str.split(":")[-1]  # Extract token from key
				tokenObj = self._getTokenFromRedis(token)
				if tokenObj:
					shouldEnqueue = False
					if tokenObj.userID in who and not but:
						shouldEnqueue = True
					elif tokenObj.userID not in who and but:
						shouldEnqueue = True

					if shouldEnqueue:
						tokenObj.enqueue(packet)
						tokens_to_update.append(tokenObj)
			
			# Batch update tokens in Redis
			for tokenObj in tokens_to_update:
				tokenKey = self._getTokenKey(tokenObj.token)
				serializedToken = self._serializeToken(tokenObj)
				pipe.set(tokenKey, serializedToken, ex=86400)
			
			pipe.execute()
		except Exception as e:
			log.error(f"Failed to enqueue packets: {e}")

	def enqueueAll(self, packet):
		"""
		Enqueue packet(s) to every connected user

		:param packet: packet bytes to enqueue
		:return:
		"""
		try:
			# Get all token keys from Redis
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			
			# Use pipeline for better performance
			pipe = glob.redis.pipeline()
			tokens_to_update = []
			
			for key in keys:
				# Decode key if it's bytes
				key_str = key.decode('utf-8') if isinstance(key, bytes) else key
				token = key_str.split(":")[-1]  # Extract token from key
				tokenObj = self._getTokenFromRedis(token)
				if tokenObj:
					tokenObj.enqueue(packet)
					tokens_to_update.append(tokenObj)
			
			# Batch update tokens in Redis
			for tokenObj in tokens_to_update:
				tokenKey = self._getTokenKey(tokenObj.token)
				serializedToken = self._serializeToken(tokenObj)
				pipe.set(tokenKey, serializedToken, ex=86400)
			
			pipe.execute()
		except Exception as e:
			log.error(f"Failed to enqueue packets to all: {e}")

	@sentry.capture()
	def usersTimeoutCheckLoop(self):
		"""
		Start timed out users disconnect loop.
		This function will be called every `checkTime` seconds and so on, forever.
		CALL THIS FUNCTION ONLY ONCE!
		:return:
		"""
		try:
			log.debug("Checking timed out clients")
			exceptions = []
			timedOutTokens = []		# timed out users
			timeoutLimit = int(time.time()) - 100
			
			# Get all token keys from Redis
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			
			for key in keys:
				# Decode key if it's bytes
				key_str = key.decode('utf-8') if isinstance(key, bytes) else key
				token = key_str.split(":")[-1]  # Extract token from key
				tokenObj = self._getTokenFromRedis(token)
				if tokenObj:
					# Check timeout (fokabot is ignored)
					if tokenObj.pingTime < timeoutLimit and tokenObj.userID != 999 and not tokenObj.irc and not tokenObj.tournament:
						# That user has timed out, add to disconnected tokens
						# We can't delete it while iterating or items() throws an error
						timedOutTokens.append(token)

			# Delete timed out users from Redis
			# i is token string (dictionary key)
			for i in timedOutTokens:
				tokenObj = self._getTokenFromRedis(i)
				if tokenObj:
					log.debug("{} timed out!!".format(tokenObj.username))
					tokenObj.enqueue(serverPackets.notification("Your connection to the server timed out."))
					# Update token in Redis after enqueueing
					self._updateTokenInRedis(tokenObj)
					try:
						logoutEvent.handle(tokenObj, None)
					except Exception as e:
						exceptions.append(e)
						log.error(
							"Something wrong happened while disconnecting a timed out client. Reporting to Sentry "
							"when the loop ends."
						)
			del timedOutTokens

			# Re-raise exceptions if needed
			if exceptions:
				raise periodicLoopException(exceptions)
		finally:
			# Schedule a new check (endless loop)
			threading.Timer(100, self.usersTimeoutCheckLoop).start()

	@sentry.capture()
	def spamProtectionResetLoop(self):
		"""
		Start spam protection reset loop.
		Called every 10 seconds.
		CALL THIS FUNCTION ONLY ONCE!

		:return:
		"""
		try:
			# Reset spamRate for every token
			# Get all token keys from Redis
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			
			# Use pipeline for better performance
			pipe = glob.redis.pipeline()
			
			for key in keys:
				# Decode key if it's bytes
				key_str = key.decode('utf-8') if isinstance(key, bytes) else key
				token = key_str.split(":")[-1]  # Extract token from key
				tokenObj = self._getTokenFromRedis(token)
				if tokenObj:
					tokenObj.spamRate = 0
					# Update token in Redis
					tokenKey = self._getTokenKey(tokenObj.token)
					serializedToken = self._serializeToken(tokenObj)
					pipe.set(tokenKey, serializedToken, ex=86400)
			
			pipe.execute()
		except Exception as e:
			log.error(f"Failed to reset spam protection: {e}")
		finally:
			# Schedule a new check (endless loop)
			threading.Timer(10, self.spamProtectionResetLoop).start()

	def deleteBanchoSessions(self):
		"""
		Remove all `peppy:sessions:*` redis keys.
		Call at bancho startup to delete old cached sessions

		:return:
		"""
		try:
			# TODO: Make function or some redis meme
			glob.redis.eval("return redis.call('del', unpack(redis.call('keys', ARGV[1])))", 0, "peppy:sessions:*")
		except redis.RedisError:
			pass
	
	def clearAllTokens(self):
		"""
		Clear all tokens from Redis and cache.
		Useful for cleanup on startup.
		
		:return:
		"""
		try:
			# Clear all token-related keys
			patterns = [
				"peppy:tokens:*",
				"peppy:user_tokens:*",
				"peppy:username_tokens:*"
			]
			
			for pattern in patterns:
				keys = glob.redis.keys(pattern)
				if keys:
					glob.redis.delete(*keys)
			
			# Clear local cache
			self._tokenCache.clear()
		except redis.RedisError:
			pass


	def tokenExists(self, username = "", userID = -1):
		"""
		Check if a token exists
		Use username or userid, not both at the same time.

		:param username: Optional.
		:param userID: Optional.
		:return: True if it exists, otherwise False
		"""
		if userID > -1:
			return True if self.getTokenFromUserID(userID) is not None else False
		else:
			return True if self.getTokenFromUsername(username) is not None else False

	def updateToken(self, tokenObj):
		"""
		Update a token in Redis after it has been modified.
		Call this after making changes to a token object's properties.
		
		:param tokenObj: token object to update
		:return:
		"""
		self._updateTokenInRedis(tokenObj)

	def getOnlineUsersCount(self):
		"""
		Get the number of online users from Redis
		
		:return: Number of online users
		"""
		try:
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			return len(keys)
		except Exception as e:
			log.error(f"Failed to get online users count: {e}")
			return 0
	
	def getAllTokens(self):
		"""
		Get all tokens as a list (for debugging/admin purposes)
		
		:return: List of token objects
		"""
		try:
			pattern = "peppy:tokens:*"
			keys = glob.redis.keys(pattern)
			tokens = []
			for key in keys:
				# Decode key if it's bytes
				key_str = key.decode('utf-8') if isinstance(key, bytes) else key
				token = key_str.split(":")[-1]
				tokenObj = self._getTokenFromRedis(token)
				if tokenObj:
					tokens.append(TokenWrapper(tokenObj, self))
			return tokens
		except Exception as e:
			log.error(f"Failed to get all tokens: {e}")
			return []

class TokenWrapper:
	"""
	Wrapper around osuToken that automatically saves changes to Redis
	"""
	def __init__(self, tokenObj, tokenList):
		# Use object.__setattr__ to avoid triggering our custom __setattr__
		object.__setattr__(self, '_tokenObj', tokenObj)
		object.__setattr__(self, '_tokenList', tokenList)
		object.__setattr__(self, '_updating', False)
	
	def __getattr__(self, name):
		attr = getattr(self._tokenObj, name)
		# If it's a method that might modify state, wrap it
		if callable(attr) and name in ['enqueue', 'resetQueue', 'joinChannel', 'partChannel', 
										'addSpectator', 'removeSpectator', 'setLocation', 
										'updateCachedStats', 'kick', 'silence']:
			def wrapped_method(*args, **kwargs):
				result = attr(*args, **kwargs)
				# Auto-save to Redis after method call
				if not self._updating:
					self._tokenList._updateTokenInRedis(self._tokenObj)
				return result
			return wrapped_method
		return attr
	
	def __setattr__(self, name, value):
		if name.startswith('_'):
			object.__setattr__(self, name, value)
		else:
			setattr(self._tokenObj, name, value)
			# Auto-save to Redis when properties change
			if not self._updating:
				self._tokenList._updateTokenInRedis(self._tokenObj)
	
	def __getitem__(self, key):
		return self._tokenObj[key]
	
	def __setitem__(self, key, value):
		self._tokenObj[key] = value
		if not self._updating:
			self._tokenList._updateTokenInRedis(self._tokenObj)
	
	def __repr__(self):
		return f"TokenWrapper({self._tokenObj})"