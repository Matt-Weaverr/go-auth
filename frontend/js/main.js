const body = document.querySelector("body");

window.addEventListener("hashchange", hashChange);
window.addEventListener("load", hashChange);
window.addEventListener("submit", submit);

function hashChange() {
    if (location.hash == "#register") {
    body.innerHTML = `
        <div class="container">
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
                    <input type="password" name="password" placeholder="Password" />
                </span>
                <span>
                    <label>Confirm Password</label>
                    <input type="password" name="confirm-password" placeholder="Password" />
                </span>
                <button type="submit">Register</button>
            </form>
            <p>
                Already have an accout?
                <a href="#login">Login</a>
            </p>
    </div>`
    return;
    }
    if (location.hash == "#forgot-password") {
        body.innerHTML = `
        <div class="container">
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
            </p>
    </div>`
    return;
    }
    if (location.hash == "#tfa-verification") {
    body.innerHTML = `
        <div class="container">
            <h1>Verify login</h1>
            <p>Enter the code sent to your email</p>
            <form>
                <span>
                    <label>Code</label>
                    <input type="text" name="otp" placeholder="Code" required />
                </span>
                <button type="submit">Submit</button>
            </form>
    </div>`
    return;
    }
    body.innerHTML = `
    <div class="container">
        <h1>Login</h1>
        <form>
            <span>
                <label>Email</label>
                <input type="email" name="email" placeholder="Email" required />
            </span>
            <span>
                <label>Password</label>
                <input type="password" name="password" placeholder="Password" />
                <a id="forgot-password" href="#forgot-password">Forgot password?</a>
            </span>
            <button type="submit">Login</button>
        </form>
        <p>
            Don't have an account?
            <a href="#register">Register</a>
        </p>
    </div>`
}

function submit(event) {
    event.preventDefault();
    switch (location.hash) {
        case "#register":
            register(
                document.querySelector('input[name="email"]').value, 
                document.querySelector('input[name="name"]').value,
                document.querySelector('input[name="password"]').value)
            break;
        default:
            login(
                document.querySelector('input[name="email"]').value,
                document.querySelector('input[name="password"]').value);
    } 
} 
