(function () {
    const contentEl = document.getElementById("dashboardContent");
    if (!contentEl) return;

    const isLoggedIn = localStorage.getItem("isLoggedIn");

    if (!isLoggedIn || isLoggedIn !== "true") {
        window.location.href = "/login";
        return;
    }

    const loggedUser = localStorage.getItem("loggedUser") || "admin";

    contentEl.innerHTML =
        "<h2>Bun venit, <span id='uname'></span>!</h2>" +
        "<hr>" +
        "<p><strong>Rol:</strong> Administrator</p>" +
        "<p><strong>Token de sesiune:</strong> <code>1234</code></p>" +
        "<p><strong>API_KEY:</strong> <code>abc123xyz-secret</code></p>" +
        "<p><strong>Date confidentiale:</strong> Salary=9000 RON, SSN=1234567</p>" +
        "<hr>" +
        "<button onclick='doLogout()' class='btn btn-danger'>Logout</button>";

    document.getElementById("uname").innerHTML = loggedUser;

    window.doLogout = function () {
        localStorage.removeItem("isLoggedIn");
        localStorage.removeItem("loggedUser");
        localStorage.removeItem("userRole");
        window.location.href = "/logout";
    };
})();
