const CACHE = {
    pre_auth_token: ''
};

function getStoredTokens() {
    return {
        accessToken: localStorage.getItem('access_token') || CACHE.access_token,
        refreshToken: localStorage.getItem('refresh_token') || CACHE.refresh_token,
    };
}

function setStoredTokens(accessToken, refreshToken) {
    CACHE.access_token = accessToken;
    CACHE.refresh_token = refreshToken;
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
}

function clearStoredTokens() {
    CACHE.access_token = '';
    CACHE.refresh_token = '';
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
}


async function login(email, password) {
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

    redirectToCallback();
}

async function register(email, name, password) {
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

async function verifyTfa(otp) {
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

    redirectToCallback();

    window.location.hash = '#';
}

async function resetPassword(email) {
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

function redirectToCallback() {
    const callbackUrl = new URLSearchParams(window.location.search).get('callback');
    if (callbackUrl) {
        window.location.href = `https://${callbackUrl}?auth_code=${encodeURIComponent(CACHE.authorization_code)}`;
    } else {
        window.location.hash = '#profile';
    }
}



