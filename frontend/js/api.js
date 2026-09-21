import { displayLoader, displayNotification, displayModal, displayModalLoader } from './ui.js';

const CACHE = {
    pre_auth_token: '',
};

export async function login(email, password) {
    displayLoader(true);
    const response = await fetch('/api/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password, remember_device: false, dfp: '' })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Login failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Login failed', true);
        return;
    }

    if (data.tfa_required) {
        CACHE.pre_auth_token = data['pre-auth_token'] || '';
        if (!CACHE.pre_auth_token) {
            displayNotification('Missing pre-auth token', true);
            return;
        }
        window.location.hash = '#tfa-verification';
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

export async function verifyTfa(otp) {
    displayLoader(true);
    const response = await fetch('/api/verify-tfa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ otp: Number(otp), token: CACHE.pre_auth_token })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Verification failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Verification failed', true);
        return;
    }

    redirectToCallback(data.authorization_code);
}

export async function resetPassword(email) {
    displayLoader(true);
    const response = await fetch('/api/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
    });

    const data = await response.json().catch(() => ({ error: true, message: 'Password reset failed' }));

    displayLoader(false);

    if (!response.ok || data.error) {
        displayNotification(data.message || 'Password reset failed', true);
        return;
    }

    displayNotification(data.message || 'Password reset sent');
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
    if (!response.ok) {
        displayNotification("Failed to logout user", true);
        return
    }
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



