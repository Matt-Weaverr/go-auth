import { login, register, verifyTfa, resetPassword, checkUserAuth, logout, updateEmail, updateName, updatePassword, enableTfa, sendTfa, sendResetPassword } from './api.js';
import { displayModal, displayNotification } from './ui.js';
import FingerprintJS from '@fingerprintjs/fingerprintjs'


const container = document.querySelector(".container");

window.addEventListener("hashchange", hashChange);
window.addEventListener("load", hashChange);
window.addEventListener("submit", submit);
window.addEventListener("click", buttonClick);

const fpPromise = FingerprintJS.load();

async function hashChange() {

    if (location.hash == "#tfa-enable") {
        container.innerHTML = `
            <h1>Enable TFA</h1>
            <p>Enter the code sent to your email</p>
            <form name="tfa-enable-form">
                <span>
                    <label>Code</label>
                    <input type="text" name="otp" placeholder="Code" required />
                </span>
                <button type="submit">Submit</button>
            </form>`;
        return;
    }

        if (location.hash == "#tfa-verify") {
        container.innerHTML = `
            <h1>Verify TFA</h1>
            <p>Enter the code sent to your email</p>
            <form name="tfa-verify-form">
                <span>
                    <label>Code</label>
                    <input type="text" name="otp" placeholder="Code" required />
                </span>
                <button type="submit">Submit</button>
                <span id="remember-device-box">
                    <input type="checkbox" name="remember-device" value="Remember device for 30 days">
                    <label>Remember device for 30 days</label>
                </span>
            </form>`;
        return;
    }

    if (location.hash == "#forgot-password") {
        const token = new URLSearchParams(window.location.search).get('token');

        if (token) {
            container.innerHTML = `
                <h1>Password reset</h1>
                <form name="reset-password-form">
                    <span>
                        <label>New password</label>
                        <input type="password" name="password" placeholder="New password" required />
                    </span>
                    <span>
                        <label>Repeat password</label>
                        <input type="password" name="confirm-password" placeholder="Repeat password" required />
                    </span>
                    <button type="submit">Submit</button>
                </form>
                <p>
                    Remember your password?
                    <a href="#login">Login</a>
                </p>`;
            return
        }

        container.innerHTML = `
            <h1>Password reset</h1>
            <form name="send-reset-password-form">
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

    let auth = await checkUserAuth();
    if (auth.authenticated) {
        renderProfile(auth.user_data);
        return;
    }

    if (location.hash == "#register") {
        container.innerHTML = `
            <h1>Register</h1>
            <form name="register-form">
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

    container.innerHTML = `
        <h1>Login</h1>
        <form name="login-form">
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

async function renderProfile(profile) {

    container.innerHTML = `
            <h1>Profile</h1>
                <div>
                    <h2>Name</h2>
                    <span><p id="profile_name">${profile.name || ''}</p><button name="edit_name">Edit</button></span>
                </div>
                <div>
                    <h2>Email</h2>
                    <span><p id="profile_email">${profile.email || ''}</p><button name="edit_email">Edit</button></span>
                </div>
                <div>
                    <h2>Password</h2>
                    <span><button name="edit_password">Edit</button></span>
                </div>
                <div>
                    <h2>TFA</h2>
                    <span>${profile.tfa_enabled ? '<button name="disable_tfa">Disable</button>' : '<button name="enable_tfa">Enable</button>'}</span>
                </div>
            <button class="logout-button" name="logout">Logout</button>
    `;
};

async function submit(event) {
    event.preventDefault();

    const form = event.target;
    const email =  form.querySelector('input[name="email"]')?.value || '';
    const password = form.querySelector('input[name="password"]')?.value || '';
    const current_password = form.querySelector('input[name="current_password"]')?.value || '';    
    const name = form.querySelector('input[name="name"]')?.value || '';
    const otp = form.querySelector('input[name="otp"]')?.value || '';
    const confirm_password = form.querySelector('input[name="confirm-password"]')?.value

    switch (form.getAttribute('name')) {
        case "register-form":
            if (password !== confirm_password) {
                displayNotification('Passwords do not match', true);
                break;
            }
            register(email, name, password);
            break;
        case "login-form":
            const dfp = await getFingerPrint();
            login(email, password, dfp);
            break;
        case "send-reset-password-form":
            sendResetPassword(email);
            break;
        case "tfa-form":
            verifyTfa(otp);
            break;
        case "change-email-form":
            updateEmail(email);
            break;
        case "change-name-form":
            updateName(name);
            break;
        case "change-password-form":
            if (password !== document.querySelector('input[name="confirm-password"]')?.value) {
                displayNotification('Passwords do not match', true);
                break;
            }
            updatePassword(current_password, password);
            break;
        case "tfa-enable-form":
            enableTfa(otp);
            break;
        case "tfa-verify-form":
            const remember_device = document.querySelector('input[name="remember-device"]').checked
            let dfp2 = ''
            if (remember_device) {
                dfp2 =  await getFingerPrint();
            }
            verifyTfa(otp, remember_device, dfp2);
            break;
        case "send-reset-password-form":
            sendResetPassword(email);
            break;
        case "reset-password-form":
            const token = new URLSearchParams(window.location.search).get('token');

            if (password !== confirm_password) {
                displayNotification('Passwords do not match', true);
                break;
            }
            resetPassword(password, token);
            break;
        default:
            return;
    }
}

function buttonClick(event) {
    let button = event.target;

    if (button.tagName.toLowerCase() !== 'button') {
        return;
    }

    switch (button.name) {
    case "edit_name":
        let currentname = document.getElementById("profile_name").textContent;
        displayModal(true, `
            <h1>Change name</h1>
            <form name="change-name-form">
                <span>
                    <input type="text" name="name" value="${currentname}" placeholder="New name" required />
                </span>
                <span class="action-buttons">
                    <button type="button" name="close_modal">Cancel</button>
                    <button type="submit" name="change_name">Submit</button>
                </span>
            </form>
            `)
        break;
    case "edit_email":
        let currentemail = document.getElementById("profile_email").textContent;
        displayModal(true, `
            <h1>Change email</h1>
            <form name="change-email-form">
                <span>
                    <input type="email" name="email" value="${currentemail}" placeholder="New email" required />
                </span>
                <span class="action-buttons">
                    <button type="button" name="close_modal">Cancel</button>
                    <button type="submit" name="change_email">Submit</button>
                </span>
            </form>
            `)
        break;
    case "edit_password":
        displayModal(true, `
            <h1>Change password</h1>
            <form name="change-password-form">
                <span>
                    <input type="password" name="current_password" placeholder="Current password" required />
                </span>
                <span>
                    <input type="password" name="password" placeholder="New password" required />
                </span>
                <span>
                    <input type="password" name="confirm-password" placeholder="Repeat new password" required />
                </span>
                <span class="action-buttons">
                    <button type="button" name="close_modal">Cancel</button>
                    <button type="submit" name="change_password">Submit</button>
                </span>
            </form>
            `)
        break;
    case "enable_tfa":
        sendTfa();
        break;
    case "disable_tfa":

        break;
    case "close_modal":
        displayModal(false, '');
        break;
    case "logout":
        logout()
        break;
    default:
        
    }
}

async function getFingerPrint() {
  const fp = await fpPromise
  const result = await fp.get()
  return result.visitorId
}
