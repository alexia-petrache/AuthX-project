if (window.location.protocol === 'file:') {
    var errEl = document.getElementById('errorMsg');
    if (errEl) {
        errEl.classList.remove('d-none');
        errEl.innerHTML = '<strong>Eroare:</strong> Aplicatia trebuie accesata prin server.<br>' +
            'Deschide: <a href="http://localhost:3000">http://localhost:3000</a>';
    }
}
