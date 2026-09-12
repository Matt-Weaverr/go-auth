const container = document.querySelector(".container");
const noticationBox = document.querySelector(".notification-box");
const loader = document.querySelector(".loader");

window.addEventListener("hashchange", hashChange);
window.addEventListener("load", hashChange);
window.addEventListener("submit", submit);

async function hashChange() {
    const code = new URLSearchParams(window.location.search).get('code');
    if (code) {
        const accessToken = await exchangeAuthorizationCode(code);
        if (accessToken) {
            window.history.replaceState({}, '', window.location.pathname);
            window.location.hash = '#profile';
            return;
        }
    }

    if (location.hash == "#profile") {
        renderProfile();
        return;
    }

    if (location.hash == "#register") {
        container.innerHTML = `
            <h1>Register</h1>
            <form>
                <span>
                    <label>Full Name</label>
                    <input type="text" name="name" placeholder="Name" required />
                </span>
                <span>
                    <label>Email</label>
                    <input type="email" name="email" placeholder="Email" required />
                </span>
                <span>
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Password" required />
                </span>
                <span>
                    <label>Confirm Password</label>
                    <input type="password" name="confirm-password" placeholder="Password" required />
                </span>
                <button type="submit">Register</button>
            </form>
            <p>
                Already have an accout?
                <a href="#login">Login</a>
            </p>`;
        return;
    }

    if (location.hash == "#forgot-password") {
        container.innerHTML = `
            <div class="loader">
                <div class="spinner"></div>
            </div>
            <h1>Password reset</h1>
            <form>
                <span>
                    <label>Email</label>
                    <input type="email" name="email" placeholder="Email" required />
                </span>
                <button type="submit">Reset password</button>
            </form>
            <p>
                Remember your password?
                <a href="#login">Login</a>
            </p>`;
        return;
    }

    if (location.hash == "#tfa-verification") {
        container.innerHTML = `
            <h1>Verify login</h1>
            <p>Enter the code sent to your email</p>
            <form>
                <span>
                    <label>Code</label>
                    <input type="text" name="otp" placeholder="Code" required />
                </span>
                <button type="submit">Submit</button>
            </form>`;
        return;
    }

    container.innerHTML = `
        <h1>Login</h1>
        <form>
            <span>
                <label>Email</label>
                <input type="email" name="email" placeholder="Email" required />
            </span>
            <span>
                <label>Password</label>
                <input type="password" name="password" placeholder="Password" required />
                <a id="forgot-password" href="#forgot-password">Forgot password?</a>
            </span>
            <button type="submit">Login</button>
        </form>
        <p>
            Don't have an account?
            <a href="#register">Register</a>
        </p>`;
}

async function renderProfile() {
    const { accessToken } = getStoredTokens();
    if (!accessToken) {
        location.hash = '#login';
        return;
    }

    const profile = await getUser(accessToken);
    if (!profile) {
        clearStoredTokens();
        location.hash = '#login';
        return;
    }

    body.innerHTML = `
        <div class="container profile-container">
            <h1>Profile</h1>
            <form id="profile-form">
                <span>
                    <label>Name</label>
                    <input type="text" name="name" value="${profile.name || ''}" />
                </span>
                <span>
                    <label>Email</label>
                    <input type="email" name="email" value="${profile.email || ''}" />
                </span>
                <span>
                    <label>New Password</label>
                    <input type="password" name="password" placeholder="Leave blank to keep current password" />
                </span>
                <button type="submit">Save changes</button>
            </form>
            <button type="button" id="logout-button" class="secondary-button">Logout</button>
        </div>
    `;

    document.querySelector('#profile-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const name = document.querySelector('input[name="name"]').value.trim();
        const email = document.querySelector('input[name="email"]').value.trim();
        const password = document.querySelector('input[name="password"]').value.trim();

        const updates = {};
        if (name) updates.name = name;
        if (email) updates.email = email;
        if (password) updates.password = password;

        const success = await updateUser(accessToken, updates);
        if (success) {
            renderProfile();
        }
    });

    document.querySelector('#logout-button').addEventListener('click', () => {
        clearStoredTokens();
        location.hash = '#login';
    });
}

function submit(event) {
    event.preventDefault();

    if (location.hash == "#profile") {
        return;
    }

    const email = document.querySelector('input[name="email"]')?.value || '';
    const password = document.querySelector('input[name="password"]')?.value || '';
    const name = document.querySelector('input[name="name"]')?.value || '';
    const otp = document.querySelector('input[name="otp"]')?.value || '';

    switch (location.hash) {
        case "#register":
            if (password !== document.querySelector('input[name="confirm-password"]')?.value) {
                console.log('Passwords do not match');
                return;
            }
            register(email, name, password);
            break;
        case "#forgot-password":
            resetPassword(email);
            break;
        case "#tfa-verification":
            verifyTfa(otp);
            break;
        default:
            login(email, password);
    }
}

function displayLoader(show) {
    if (show) {
        loader.style.display = 'flex';
    } else {
        loader.style.display = 'none';
    }
}

let noficationcount = 0;
function displayNotification(message, error = false) {
    if (error) {
        noticationBox.insertAdjacentHTML('afterbegin', `<div class="notification error" id="notification-${noficationcount}"><p>Error: ${message}</p></div>`);
    } else {
        noticationBox.insertAdjacentHTML('afterbegin', `<div class="notification success" id="notification-${noficationcount}"><p>Success: ${message}</p></div>`);
    }

    let notifid = noficationcount;

    setTimeout(() => {
        const notification = document.getElementById(`notification-${notifid}`);
        if (notification) {
            notification.remove();
        }
    }, 5000);
    noficationcount++;
}
