class_name Sentinela extends Object


var crypto := Crypto.new()
var key := crypto.generate_rsa(4096)


func encrypt(value: String) -> PackedByteArray:
	return crypto.encrypt(key, value.to_utf8_buffer())


func decrypt(value: PackedByteArray) -> PackedByteArray:
	return crypto.decrypt(key, value)


func verify(signature: PackedByteArray, value: String) -> bool:
	return crypto.verify(
		HashingContext.HASH_SHA256,
		value.sha256_buffer(),
		signature,
		key)


func sign(value: String) -> PackedByteArray:
	return crypto.sign(
		HashingContext.HASH_SHA256,
		value.sha256_buffer(),
		key)


func dispose() -> void:
	pass
