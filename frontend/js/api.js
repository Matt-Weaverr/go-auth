const BACKEND_URL = "http://127.0.0.1:8000";

async function login(email, password) {
    let response = await fetch(`${BACKEND_URL}/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({email: email, password: password})
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

    if (data.tfa) {
        console.log('tfa required');
        return
    }

    //redirect

}

async function register(email, name, password) {
    let response = await fetch(`${BACKEND_URL}/register`, {
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
