var delBtn = document.querySelector('.btn-delete-single');
if (delBtn) {
    delBtn.addEventListener('click', function (e) {
        if (!confirm('Ești sigur că vrei să ștergi acest ticket?')) {
            e.preventDefault();
        }
    });
}
