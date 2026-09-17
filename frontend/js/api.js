import { displayLoader, displayNotification, displayModel, displayModelLoader } from './ui.js';

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



function redirectToCallback(code) {
    const callbackUrl = new URLSearchParams(window.location.search).get('callback');
    if (callbackUrl) {
        window.location.href = `https://${callbackUrl}?auth_code=${code}`;
    } else {
        window.location.hash = '#profile';
    }
}



