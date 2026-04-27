document.querySelectorAll('.btn-delete').forEach(function (btn) {
    btn.addEventListener('click', function (e) {
        if (!confirm('Ești sigur că vrei să ștergi acest ticket?')) {
            e.preventDefault();
        }
    });
});
