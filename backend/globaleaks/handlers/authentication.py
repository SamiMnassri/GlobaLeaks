# -*- coding: utf-8 -*-
#
# Handlers dealing with platform authentication
import ipaddress

from random import SystemRandom
from six import text_type, binary_type
from sqlalchemy import and_, or_
from twisted.internet.defer import inlineCallbacks, returnValue

from globaleaks.utils import security
from globaleaks.handlers.base import BaseHandler, Sessions, new_session
from globaleaks.models import InternalTip, User, UserTenant, WhistleblowerTip, get_auth_token
from globaleaks.orm import transact
from globaleaks.rest import errors, requests
from globaleaks.settings import Settings
from globaleaks.state import State
from globaleaks.utils.utility import datetime_now, deferred_sleep, log, parse_csv_ip_ranges_to_ip_networks
from globaleaks.utils.crypto import AsymmetricalCryptographyContext

def random_login_delay():
    """
    in case of failed_login_attempts introduces
    an exponential increasing delay between 0 and 42 seconds

        the function implements the following table:
            ----------------------------------
           | failed_attempts |      delay     |
           | x < 5           | 0              |
           | 5               | random(5, 25)  |
           | 6               | random(6, 36)  |
           | 7               | random(7, 42)  |
           | 8 <= x <= 42    | random(x, 42)  |
           | x > 42          | 42             |
            ----------------------------------
    """
    failed_attempts = Settings.failed_login_attempts

    if failed_attempts >= 5:
        n = failed_attempts * failed_attempts

        min_sleep = failed_attempts if failed_attempts < 42 else 42
        max_sleep = n if n < 42 else 42

        return SystemRandom().randint(min_sleep, max_sleep)

    return 0


@transact
def login_whistleblower(session, tid, receipt, client_using_tor):
    """
    login_whistleblower returns a session
    """
    hashed_receipt = security.hash_password(receipt, State.tenant_cache[tid].receipt_salt)
    result = session.query(WhistleblowerTip, InternalTip) \
                    .filter(WhistleblowerTip.receipt_hash == text_type(hashed_receipt, 'utf-8'),
                            WhistleblowerTip.tid == tid,
                            InternalTip.id == WhistleblowerTip.id,
                            InternalTip.tid == WhistleblowerTip.tid).first()

    if result is None:
        log.debug("Whistleblower login: Invalid receipt")
        Settings.failed_login_attempts += 1
        raise errors.InvalidAuthentication

    wbtip, itip = result[0], result[1]

    if not client_using_tor and not State.tenant_cache[tid]['https_whistleblower']:
        log.err("Denied login request over clear Web for role 'whistleblower'")
        raise errors.TorNetworkRequired

    itip.wb_last_access = datetime_now()

    return new_session(tid, wbtip.id, 'whistleblower', False, wbtip.crypto_prv_key)


@transact
def login(session, tid, username, password, client_using_tor, client_ip, token=''):
    """
    login returns a session
    """
    user = None

    tenant_condition = and_(UserTenant.user_id == User.id, UserTenant.tenant_id == tid)

    if token:
        user = session.query(User).filter(User.auth_token == token,
                                          User.state != u'disabled',
                                          tenant_condition).one_or_none()
    else:
        users = session.query(User).filter(User.username == username,
                                           User.state != u'disabled',
                                           tenant_condition).distinct()
        for u in users:
            if security.check_password(password, u.salt, u.password):
                user = u

    if user is None:
        log.debug("Login: Invalid credentials")
        Settings.failed_login_attempts += 1
        raise errors.InvalidAuthentication

    if not client_using_tor and not State.tenant_cache[tid]['https_' + user.role]:
        log.err("Denied login request over Web for role '%s'" % user.role)
        raise errors.TorNetworkRequired

    # Check if we're doing IP address checks today
    if State.tenant_cache[tid]['ip_filter_authenticated_enable']:
        ip_networks = parse_csv_ip_ranges_to_ip_networks(
            State.tenant_cache[tid]['ip_filter_authenticated']
        )

        if isinstance(client_ip, binary_type):
            client_ip = client_ip.decode()

        client_ip_obj = ipaddress.ip_address(client_ip)

        # Safety check, we always allow localhost to log in
        success = False
        if client_ip_obj.is_loopback is True:
            success = True

        for ip_network in ip_networks:
            if client_ip_obj in ip_network:
                success = True

        if success is not True:
            raise errors.AccessLocationInvalid

    # Generate a PGP key if necessary
    if user.crypto_prv_key is None or user.crypto_prv_key == "":
        from globaleaks.handlers.admin.user import db_generate_private_keys_for_user
        db_generate_private_keys_for_user(session, tid, user, password)

    user.last_login = datetime_now()
    context = AsymmetricalCryptographyContext.load_full_keyset(
        user.crypto_prv_key,
        user.crypto_key,
        AsymmetricalCryptographyContext.derive_scrypted_passphrase(password, State.tenant_cache[tid].receipt_salt)
    )

    return new_session(tid, user.id, user.role, user.password_change_needed, context.get_decrypted_private_key())


@transact
def get_multitenant_auth_token(session, user_id, tid):
    # check that the user can really access the tenant requested
    count = session.query(UserTenant).filter(UserTenant.user_id == user_id,
                                             UserTenant.tenant_id == tid).count()

    if not count:
        return u''

    token = get_auth_token()
    session.query(User.id).filter(User.id == user_id).update({'auth_token': token})
    return token


class AuthenticationHandler(BaseHandler):
    """
    Login handler for admins and recipents and custodians
    """
    check_roles = 'unauthenticated'
    uniform_answer_time = True

    @inlineCallbacks
    def post(self):
        request = self.validate_message(self.request.content.read(), requests.AuthDesc)

        delay = random_login_delay()
        if delay:
            yield deferred_sleep(delay)

        tid = int(request['tid'])
        if tid == 0:
             tid = self.request.tid

        session = yield login(tid,
                              request['username'],
                              request['password'],
                              self.request.client_using_tor,
                              self.request.client_ip,
                              request['token'])

        log.debug("Login: Success (%s)" % session.user_role)

        if tid != self.request.tid:
            token = yield get_multitenant_auth_token(session.user_id, tid)

            returnValue({
                'redirect': 'https://%s/#/login?token=%s' % (State.tenant_cache[tid].hostname, token)
            })

        returnValue(session.serialize())


class ReceiptAuthHandler(BaseHandler):
    """
    Receipt handler used by whistleblowers
    """
    check_roles = 'unauthenticated'
    uniform_answer_time = True

    @inlineCallbacks
    def post(self):
        request = self.validate_message(self.request.content.read(), requests.ReceiptAuthDesc)

        receipt = request['receipt']

        delay = random_login_delay()
        if delay:
            yield deferred_sleep(delay)

        session = yield login_whistleblower(self.request.tid, receipt, self.request.client_using_tor)

        log.debug("Login: Success (%s)" % session.user_role)

        returnValue(session.serialize())


class SessionHandler(BaseHandler):
    """
    Session handler for authenticated users
    """
    check_roles = {'admin','receiver','custodian','whistleblower'}

    def get(self):
        """
        Refresh and retrive session
        """
        return self.current_user.serialize()

    def delete(self):
        """
        Logout
        """
        del Sessions[self.current_user.id]


class TenantAuthSwitchHandler(BaseHandler):
    """
    Login handler for switching tenant
    """
    check_roles = {'admin','receiver','custodian'}
    uniform_answer_time = True

    @inlineCallbacks
    def get(self, tid):
        token = yield get_multitenant_auth_token(self.current_user.user_id, tid)

        returnValue({
            'redirect': 'https://%s/#/login?token=%s' % (State.tenant_cache[tid].hostname, token)
        })
