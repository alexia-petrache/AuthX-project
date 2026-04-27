const DEMO_USER     = "admin@authx.com";
const DEMO_PASS     = "123";
const DEMO_PASS_B64 = btoa(DEMO_PASS);

console.log("Username :", DEMO_USER);
console.log("Password :", DEMO_PASS);
console.log("Pass B64 :", DEMO_PASS_B64);
console.log("Decoded  :", atob(DEMO_PASS_B64));

(function handleURLXSS() {
    const params        = new URLSearchParams(window.location.search);
    const usernameParam = params.get("username");

    if (usernameParam) {
        const errEl = document.getElementById("errorMsg");
        if (errEl) {
            errEl.classList.remove("d-none");
            errEl.innerHTML = "Utilizatorul <b>'" + usernameParam + "'</b> nu a fost gasit.";
        }
        const inputEl = document.getElementById("username");
        if (inputEl) inputEl.value = usernameParam;
    }
})();

document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const errEl    = document.getElementById('errorMsg');
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (window.location.protocol === 'file:') {
        errEl.classList.remove('d-none');
        errEl.innerHTML = '<strong>Eroare:</strong> Aplicatia trebuie accesata prin server.<br>' +
            'Deschide: <a href="http://localhost:3000">http://localhost:3000</a>';
        return;
    }

    try {
        const resp = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password)
        });

        if (resp.ok) {
            localStorage.setItem('isLoggedIn', 'true');
            localStorage.setItem('loggedUser', username);
            window.location.href = '/dashboard.html';
        } else {
            const html = await resp.text();
            document.open();
            document.write(html);
            document.close();
        }
    } catch (err) {
        errEl.classList.remove('d-none');
        errEl.innerHTML = '<strong>Eroare conexiune:</strong> Serverul nu raspunde.<br>' +
            '<a href="http://localhost:3000">http://localhost:3000</a>';
    }
});
