(function () {
    'use strict';

    var form = document.getElementById('loginForm');
    var modal = document.getElementById('errorModal');
    var errorList = document.getElementById('errorList');

    var fields = {
        email: document.getElementById('email'),
        password: document.getElementById('password')
    };

    var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

    /* ---------- Show / hide password (eye button) ---------- */

    document.querySelectorAll('.toggle-password').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var input = document.getElementById(btn.dataset.target);
            var icon = btn.querySelector('i');
            var showing = input.type === 'text';

            input.type = showing ? 'password' : 'text';
            icon.className = showing ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
            btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
        });
    });

    /* ---------- Error popup ---------- */

    var lastFocused = null;

    function openModal(messages, firstInvalid) {
        errorList.innerHTML = '';
        messages.forEach(function (msg) {
            var li = document.createElement('li');
            li.textContent = msg;
            errorList.appendChild(li);
        });

        lastFocused = firstInvalid;
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        modal.querySelector('.btn-modal').focus();
    }

    function closeModal() {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        if (lastFocused) { lastFocused.focus(); }
    }

    modal.addEventListener('click', function (e) {
        // Close on the X, the Okay button, or a click on the dark background
        if (e.target === modal || e.target.closest('[data-close]')) {
            closeModal();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && modal.classList.contains('open')) {
            closeModal();
        }
    });

    /* ---------- Submit ---------- */

    // Remove the red border as soon as the user edits a field again
    Object.keys(fields).forEach(function (key) {
        fields[key].addEventListener('input', function () {
            fields[key].classList.remove('is-invalid');
        });
    });

    form.addEventListener('submit', function (e) {
        var errors = [];
        var invalid = [];

        var email = fields.email.value.trim();
        var password = fields.password.value;

        if (email === '') {
            errors.push('Email address is required.');
            invalid.push(fields.email);
        } else if (!emailRegex.test(email)) {
            errors.push('Please enter a valid email address.');
            invalid.push(fields.email);
        }

        if (password === '') {
            errors.push('Password is required.');
            invalid.push(fields.password);
        }

        Object.keys(fields).forEach(function (key) {
            fields[key].classList.toggle('is-invalid', invalid.indexOf(fields[key]) !== -1);
        });

        if (errors.length) {
            e.preventDefault();
            openModal(errors, invalid[0]);
        }
        // No errors: the form goes to Flask, which checks the email and password
    });

    // If Flask sent errors back, the popup is already open: focus it and remember the first bad field
    if (modal.classList.contains('open')) {
        lastFocused = document.querySelector('.input.is-invalid');
        modal.querySelector('.btn-modal').focus();
    }
})();