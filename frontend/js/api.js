const CACHE = {}

async function login(email, password) {
    let response = await fetch('/api/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },

        body: JSON.stringify({email: email, password: password, remember_device: false, dfp: ""})
    }
    )

    if (response.status !== 200) {
        //fail
        return
    }

    let data = await response.json();

    if (data.error) {
        console.log(data.message);
        return;
    }

    if (data.tfa_required) {
        CACHE.pre_auth_token = data.pre_auth_token;
        window.location.hash = '#tfa-verification';
        return;
    }

    let callbackurl = new URLSearchParams(window.location.search).get('callback');
    window.location.href = `${callbackurl}?code=${authorization_code}`;

}

async function register(email, name, password) {
    let response = await fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({email: email, name: name, password: password})
    }
    )
    if (response.status !== 200) {
        //fail
        return
    }
    let data = await response.json();
    if (data.error) {
        console.log(data.message);
        return
    }
    login(email, password);
}

async function verifyTfa(otp) {
    let response = await fetch('/api/verify-tfa', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({otp: otp, token: CACHE.pre_auth_token})
    })
    if (response.status !== 200) {
        //fail
        return
    }
    let data = await response.json();
    if (data.error) {
        console.log(data.message);
        return;
    }


}


