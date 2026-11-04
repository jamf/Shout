//
//  Session.swift
//  Shout
//
//  Created by Jake Heiser on 3/4/18.
//

import Foundation
import CSSH
import Socket

/// Direct bindings to libssh2_session
public class Session {

    private static let initResult = libssh2_init(0)
    
    private let cSession: OpaquePointer
    private var agent: Agent?
    
    var blocking: Int32 {
        get {
            return libssh2_session_get_blocking(cSession)
        }
        set(newValue) {
            libssh2_session_set_blocking(cSession, newValue)
        }
    }
    
    init() throws {
        guard Session.initResult == 0 else {
            throw SSHError.genericError("libssh2_init failed")
        }
        
        guard let cSession = libssh2_session_init_ex(nil, nil, nil, nil) else {
            throw SSHError.genericError("libssh2_session_init failed")
        }
        
        self.cSession = cSession
    }
    
    func handshake(over socket: Socket) throws {
        let code = libssh2_session_handshake(cSession, socket.socketfd)
        try SSHError.check(code: code, session: cSession)
    }
    
    func authenticate(username: String, privateKey: String, publicKey: String, passphrase: String?) throws {
        let code = libssh2_userauth_publickey_fromfile_ex(cSession,
                                                          username,
                                                          UInt32(username.count),
                                                          publicKey,
                                                          privateKey,
                                                          passphrase)
        try SSHError.check(code: code, session: cSession)
    }
    
    func authenticate(username: String, password: String) throws {
        let code = libssh2_userauth_password_ex(cSession,
                                                username,
                                                UInt32(username.count),
                                                password,
                                                UInt32(password.count),
                                                nil)
        try SSHError.check(code: code, session: cSession)
    }
    
    func openSftp() throws -> SFTP  {
        return try SFTP(session: self, cSession: cSession)
    }
    
    func openCommandChannel() throws -> Channel {
        return try Channel.createForCommand(cSession: cSession)
    }

    func openSCPChannel(fileSize: Int64, remotePath: String, permissions: FilePermissions) throws -> Channel {
        return try Channel.createForSCP(cSession: cSession, fileSize: fileSize, remotePath: remotePath, permissions: permissions)
    }
    
    func openAgent() throws -> Agent {
        if let agent = agent {
            return agent
        }
        let newAgent = try Agent(cSession: cSession)
        agent = newAgent
        return newAgent
    }

    /// The timeout last passed to `setTimeout` (0 = none). libssh2 only enforces its own
    /// timeout in blocking mode, so non-blocking loops must enforce it themselves.
    private(set) var timeoutMilliseconds = 0

    public func setTimeout(milliseconds: Int) {
        timeoutMilliseconds = milliseconds
        libssh2_session_set_timeout(cSession, milliseconds)
    }

    /// Waits until the socket is ready in the direction libssh2 is blocked on (or `maxWaitMilliseconds` elapses).
    func waitForSocket(_ socketfd: Int32, maxWaitMilliseconds: Int32) {
        let directions = libssh2_session_block_directions(cSession)
        var events: Int16 = 0
        if directions & LIBSSH2_SESSION_BLOCK_INBOUND != 0 { events |= Int16(POLLIN) }
        if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 { events |= Int16(POLLOUT) }
        if events == 0 { events = Int16(POLLIN) }
        var descriptor = pollfd(fd: socketfd, events: events, revents: 0)
        _ = poll(&descriptor, 1, maxWaitMilliseconds)
    }

    func timeoutError() -> SSHError {
        return SSHError.codeError(code: LIBSSH2_ERROR_TIMEOUT, session: cSession)
    }

    deinit {
        libssh2_session_free(cSession)
    }
    
}
