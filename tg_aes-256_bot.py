import binascii
from config import bot_token
from typing import Tuple, Union
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import logging
from telegram.ext import Updater, CommandHandler, ConversationHandler, MessageHandler, Filters, CallbackContext
from telegram import ReplyKeyboardMarkup, ReplyKeyboardRemove, Update


def to_bytes(string: str) -> bytes:
    _bytes = string.encode(encoding='utf-8')
    return _bytes


def from_bytes(b_string: bytes) -> str:
    _str = b_string.decode()
    return _str


def generate_key(password: str) -> bytes:
    _pass = to_bytes(password)
    hash_key = SHA256.new()
    hash_key.update(_pass)
    secret_key = hash_key.digest()
    return secret_key


def encrypt_aes_gcm(msg: str, password: str) -> Tuple[bytes, Union[bytes, bytearray, memoryview], bytes]:
    secret_key = generate_key(password)
    aesCipher = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(to_bytes(msg))
    return ciphertext, aesCipher.nonce, authTag


def decrypt_aes_gcm(encryptedMsg: str, password: str) -> str:
    (ciphertext, nonce, authTag) = encryptedMsg
    secret_key = generate_key(password)
    aesCipher = AES.new(secret_key, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return from_bytes(plaintext)


logger = logging.getLogger(__name__)

CHOOSING, MSG_TAG, TYPING_MSG, TYPING_PASS, PWD_STATE = range(5)

reply_keyboard = [['encrypt message', 'decrypt message']]
choosing_keyboard = [['delete', 'save']]

markup = ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True, resize_keyboard=True)
choosing_markup = ReplyKeyboardMarkup(choosing_keyboard, one_time_keyboard=True, resize_keyboard=True)


def start(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    bot_msg_id = update.message.reply_text(
        f"Hi, I can en(de)crypt a messages for you.\n"
        f"You can type/tap /restart at any moment to restart the conversation.")
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    bot_msg_id_ = update.message.reply_text(
        f"I will clear the history(from chat and server side) after all, "
        f"so be careful, but first choose one:",
        reply_markup=markup, )
    context.user_data['trash_ids'].append(bot_msg_id_.message_id)
    return CHOOSING


def first_choice(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['choice'] = text
    bot_msg_id = update.message.reply_text(f"Let's make a tag:",
                                           reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return MSG_TAG


def msg_tag(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['tag'] = text
    bot_msg_id = update.message.reply_text(
        f"Now send me the message to {context.user_data['choice'].split()[0]}:")
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return TYPING_MSG


def received_msg(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['message'] = text
    bot_msg_id = update.message.reply_text(
        f"Now send me the password to {context.user_data['choice'].split()[0]} you message.\n")
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return TYPING_PASS


def received_pass(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    text = update.message.text
    context.user_data['password'] = text
    context.user_data['pwd_msg_id'] = msg_id
    bot_msg_id = update.message.reply_text(f"Do you wanna save the password?",
                                           reply_markup=choosing_markup)
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return PWD_STATE


def received_password_state(update: Update, context: CallbackContext):
    text = update.message.text
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    if text == 'save':
        context.user_data['pwd_state'] = text
    elif text == 'delete':
        context.user_data['pwd_state'] = text
    bot_msg_id = update.message.reply_text(f"One moment...",
                                           reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    result_msg(update, context)
    return ConversationHandler.END


def result_msg(update: Update, context: CallbackContext):
    method_choice = context.user_data['choice']
    msg_to = context.user_data['message']
    pass_to = context.user_data['password']
    if method_choice == 'encrypt message':
        raw_res_msg = encrypt_aes_gcm(msg_to, pass_to)
        res_msg_list = [binascii.hexlify(chunk).decode('utf-8') for chunk in raw_res_msg]
        res_msg = ':'.join(res_msg_list)
    elif method_choice == 'decrypt message':
        try:
            raw_encr_msg = msg_to.split(":")
            encr_msg_tuple = tuple(binascii.unhexlify(chunk) for chunk in raw_encr_msg)
            res_msg = decrypt_aes_gcm(encr_msg_tuple, pass_to)
            print(type(res_msg))
        except Exception as e:
            print(f"Oops! not valid msg {e.__class__}")
            return wrong_data(update, context)
            # return None  # ConversationHandler.END
    if context.user_data['pwd_state'] == 'save':
        update.message.reply_text(
            f"tag: {context.user_data['tag']}\n"
            f"password: {context.user_data['password']}")
    elif context.user_data['pwd_state'] == 'delete':
        update.message.reply_text(
            f"tag: {context.user_data['tag']}")
    update.message.reply_text(f"{res_msg}")
    for itm in context.user_data['trash_ids']:
        try:
            context.bot.delete_message(update.message.chat_id, itm)
        except Exception as e:
            print(f"Oops, something goes wrong in {result_msg.__name__} func while deleting trash_ID's. {e.__class__}")
    context.user_data.clear()
    # return ConversationHandler.END


def end_conv(update: Update, context: CallbackContext) -> int:
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    user = update.message.from_user
    logger.info("User %s canceled the conversation.", user.first_name)
    bot_msg_id = update.message.reply_text(
        'Ok, type/tap /start to start the conversation again', reply_markup=ReplyKeyboardRemove())
    for itm in context.user_data['trash_ids']:
        try:
            context.bot.delete_message(update.message.chat_id, itm)
        except Exception as e:
            print(f"Oops, something goes wrong in {end_conv.__name__} func. {e.__class__}")
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return ConversationHandler.END


def wrong_data(update: object, context: CallbackContext):
    msg_id = update.message.message_id
    context.user_data['trash_ids'].append(msg_id)
    bot_msg_id = update.message.reply_text(
        f"Oops, the password or message structure is incorrect,"
        f"\ntype/tap /restart to restart the conversation",
        reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return ConversationHandler.END


def error_handler(update: object, context: CallbackContext):
    msg_id = update.message.message_id
    context.user_data.setdefault('trash_ids', []).append(msg_id)
    logger.error(msg="Exception while handling an update:", exc_info=context.error, )
    bot_msg_id = update.message.reply_text(
        f"Nope, type/tap /start or /restart to start/restart the conversation",
        reply_markup=ReplyKeyboardRemove())
    context.user_data['trash_ids'].append(bot_msg_id.message_id)
    return end_conv


def main() -> None:
    updater = Updater(bot_token)

    # Get the dispatcher to register handlers
    dispatcher = updater.dispatcher

    # Add conversation handler
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            CHOOSING: [
                MessageHandler(Filters.regex('^(encrypt message|decrypt message)$') & ~Filters.command, first_choice),
            ],
            MSG_TAG: [
                MessageHandler(Filters.text & ~Filters.command, msg_tag),
            ],
            TYPING_MSG: [
                MessageHandler(Filters.text & ~Filters.command, received_msg),

            ],
            TYPING_PASS: [
                MessageHandler(Filters.text & ~Filters.command, received_pass),
            ],

            PWD_STATE: [
                MessageHandler(Filters.regex('^(delete|save)$') & ~Filters.command, received_password_state),
            ],
        },
        fallbacks=[CommandHandler('restart', end_conv)],
    )

    dispatcher.add_handler(conv_handler)
    dispatcher.add_error_handler(error_handler)
    dispatcher.add_handler(MessageHandler(Filters.text, error_handler))
    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
