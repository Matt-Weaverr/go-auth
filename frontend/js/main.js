import { login, register, verifyTfa, resetPassword, getProfile } from './api.js';

const container = document.querySelector(".container");

window.addEventListener("hashchange", hashChange);
window.addEventListener("load", hashChange);
window.addEventListener("submit", submit);

async function hashChange() {

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

    let profile = await getProfile();

    container.innerHTML = `
            <h1>Profile</h1>
                <div>
                    <h2>Name</h2>
                    <span><p>${profile.name || ''}</p><button>Edit</button></span>
                </div>
                <div>
                    <h2>Email</h2>
                    <span><p>${profile.email || ''}</p><button>Edit</button></span>
                </div>
                <div>
                    <h2>Password</h2>
                    <span><button>Edit</button></span>
                </div>
                <div>
                    <h2>TFA</h2>
                    <span>${profile.tfa_enabled ? '<button>Disable</button>' : '<button>Enable</button>'}</span>
                </div>
            <button class="logout-button">Logout</button>
    `;
};

function submit(event) {
    event.preventDefault();


    
    if (location.hash == "#profile") {
        return;
    }

    const form = event.target;
    const email =  form.querySelector('input[name="email"]')?.value || '';
    const password = form.querySelector('input[name="password"]')?.value || '';
    const name = form.querySelector('input[name="name"]')?.value || '';
    const otp = form.querySelector('input[name="otp"]')?.value || '';

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
