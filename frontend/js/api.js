import { displayLoader, displayNotification, displayModal, displayModalLoader } from './ui.js';

const CACHE = {
    pre_auth_token: '',
};

export async function login(email_param, password_param, dfp_param) {
    displayLoader(true);
    const response = await fetch('/api/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email_param, password: password_param, dfp: dfp_param })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Login failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Login failed', true);
        return;
    }

    if (data.tfa_required) {
        CACHE.pre_auth_token = data['pre_auth_token'] || '';
        if (!CACHE.pre_auth_token) {
            displayNotification('Missing pre auth token', true);
            return;
        }
        window.location.hash = '#tfa-verify';
        return;
    }
    redirectToCallback(data.authorization_code);
}

export async function register(email, name, password) {
    displayLoader(true);
    const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, name, password })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Registration failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Registration failed', true);
        return;
    }

    await login(email, password);
}

export async function verifyTfa(otp, remember_device_param, dfp_param) {
    displayLoader(true);
    const response = await fetch('/api/verify-tfa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ otp: Number(otp), token: CACHE.pre_auth_token, remember_device: remember_device_param ? true : false, dfp: dfp_param})
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Verification failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Verification failed', true);
        return;
    }

    redirectToCallback(data.authorization_code);
}

export async function sendResetPassword(email) {
    displayLoader(true);
    const response = await fetch('/api/reset-password-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
    });
    displayLoader(false);

    if (!response.ok) {
        displayNotification('Password reset failed', true);
        return;
    }

    displayNotification('Password reset link sent', false);
    window.location.hash = '#login';
}

export async function resetPassword(new_password_param, token_param) {
    displayLoader(true);
    const response = await fetch('/api/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ new_password: new_password_param, token: token_param })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Password reset failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Password reset failed', true);
        return;
    }

    displayNotification(data.message || 'Password reset successful', false);
    window.location.hash = '#login';
}

export async function getProfile() {
    displayLoader(true);
    const response = await fetch('/api/user', {
        method: 'POST',
    });
    displayLoader(false);

    if (!response.ok) {
        window.location.hash = '#login';
        return;
    }
    return await response.json().catch(() => ({}));
}

export async function checkUserAuth() {
    displayLoader(true);
    const response = await fetch('/api/user', {
        method: 'POST',
    });
    if (response.ok) {
        let data = await response.json().catch(() => ({}))
        displayLoader(false);
        if (JSON.stringify(data) === '{}') {
            displayNotification('Failed to fetch user data', true);
        }
        return { authenticated: true, user_data: data };
    }
    displayLoader(false);
    return { authenticated: false, user_data: {} };
}

export async function logout() {
    displayLoader(true);
    const response = await fetch('/api/logout', {
        method: 'POST',
    });
    displayLoader(false);
    window.location.hash = "#login";
}

export async function updateEmail(email_param) {
    displayLoader(true);
    const response = await fetch('/api/update/email', {
        method: 'POST',
        body: JSON.stringify({ email: email_param})
    });
    displayLoader(false);
    if (!response.ok) {
        displayNotification("Failed to update user email", true);
        return
    }
    displayNotification("Updated user email", false);
    displayModal(false, '');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
}

export async function updateName(name_param) {
    displayLoader(true);
    const response = await fetch('/api/update/name', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name: name_param})
    });
    displayLoader(false);
    if (!response.ok) {
        displayNotification("Failed to update user name", true);
        return
    }
    displayNotification("Updated user name", false);
    displayModal(false, '');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
}

export async function updatePassword(current_password_param, new_password_param) {
    displayLoader(true);
    const response = await fetch('/api/update/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: current_password_param, new_password: new_password_param})
    });
    displayLoader(false);
    if (response.status === 401) {
        displayNotification("Incorrect password", true);
        return
    }
    if (!response.ok) {
        displayNotification("Failed to update user password", true);
        return
    }
    displayNotification("Updated user password", false);
    displayModal(false, '');
}

export async function sendTfa() {
    displayLoader(true);
    const response = await fetch('/api/send-tfa', {
        method: 'POST'
    });
    displayLoader(false);
    if (!response.ok) {
        displayNotification("Failed to send tfa code", true);
        return
    }
    window.location.hash = "#tfa-enable"
}

export async function enableTfa(otp_param) {
    displayLoader(true);
    const response = await fetch('/api/enable-tfa', {
        method: 'POST',
        body: JSON.stringify({ otp: otp_param})
    });
    
    const data = await response.json().catch(() => ({ error: true, message: 'Failed to verify tfa' }));

    displayLoader(false);
    if (!response.ok) {
        displayNotification("Failed to verify tfa", true);
        return
    }
    
    if (data.error) {
        displayNotification(data.message, true);
        return
    }
    console.log("trigger");
    displayNotification("TFA Enabled", false);
    window.location.hash = ''
}



function redirectToCallback(code) {
    const callbackUrl = new URLSearchParams(window.location.search).get('callback');
    if (callbackUrl) {
        window.location.href = `https://${callbackUrl}?auth_code=${code}`;
    } else {
        if (location.hash !== '') {
            window.location.hash = '';
        } else {
            window.dispatchEvent(new HashChangeEvent('hashchange'));
        }
    }
}



