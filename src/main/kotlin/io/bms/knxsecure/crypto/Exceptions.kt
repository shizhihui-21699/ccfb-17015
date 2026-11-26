package io.bms.knxsecure.crypto

/** Base type for cryptographic or protocol security failures. */
open class KnxSecureException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Authentication tag / MAC verification failed. */
class MacVerificationException(message: String) : KnxSecureException(message)

/** Malformed or out-of-spec frame. */
class ProtocolException(message: String, cause: Throwable? = null) : KnxSecureException(message, cause)

/** A frame was rejected because of replay / sequence-number rules. */
class ReplayException(message: String) : KnxSecureException(message)
