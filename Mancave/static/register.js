(function () {
    'use strict';

    var form = document.getElementById('registerForm');
    var modal = document.getElementById('errorModal');
    var errorList = document.getElementById('errorList');

    var fields = {
        username: document.getElementById('username'),
        bday: document.getElementById('bday'),
        first: document.getElementById('first_name'),
        last: document.getElementById('last_name'),
        number: document.getElementById('number'),
        email: document.getElementById('email'),
        password: document.getElementById('password'),
        confirm: document.getElementById('confirm_password')
    };

    /* ---------- Validation rules ---------- */

    var nameRegex = /^[A-Za-z][A-Za-z .'-]*$/;
    var usernameRegex = /^[A-Za-z0-9_.-]{1,50}$/;
    var mobileRegex = /^(09\d{9}|\+639\d{9})$/;
    var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

    var passwordRules = {
        length: function (v) { return v.length >= 8; },
        lower: function (v) { return /[a-z]/.test(v); },
        upper: function (v) { return /[A-Z]/.test(v); },
        underscore: function (v) { return v.indexOf('_') !== -1; },
        number: function (v) { return /\d/.test(v); }
    };

    /* ---------- Password requirements (appear while typing) ---------- */

    var checklist = document.getElementById('passwordChecklist');
    var countEl = document.getElementById('passwordCount');
    var ruleItems = document.querySelectorAll('#passwordRules li');

    function updateChecklist() {
        var value = fields.password.value;
        var met = 0;

        // Show the box as soon as something is typed, hide it when the field is empty
        checklist.classList.toggle('show', value.length > 0);

        ruleItems.forEach(function (item) {
            var passed = passwordRules[item.dataset.rule](value);
            item.classList.toggle('met', passed);
            if (passed) { met++; }
        });

        countEl.textContent = met + '/' + ruleItems.length;
        checklist.classList.toggle('complete', met === ruleItems.length);
    }

    fields.password.addEventListener('input', updateChecklist);

    /* ---------- Show / hide password (eye buttons) ---------- */

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

        function fail(field, message) {
            errors.push(message);
            invalid.push(field);
        }

        var first = fields.first.value.trim();
        var last = fields.last.value.trim();
        var username = fields.username.value.trim();
        var bday = fields.bday.value;
        var number = fields.number.value.trim();
        var email = fields.email.value.trim();
        var password = fields.password.value;
        var confirm = fields.confirm.value;

        if (username === '') {
            fail(fields.username, 'Username is required.');
        } else if (!usernameRegex.test(username)) {
            fail(fields.username, 'Username may contain letters, numbers, periods, hyphens and underscores.');
        }

        if (bday === '') {
            fail(fields.bday, 'Birthday is required.');
        } else if (bday > new Date().toISOString().slice(0, 10)) {
            fail(fields.bday, 'Birthday cannot be in the future.');
        }

        // First name
        if (first === '') {
            fail(fields.first, 'First name is required.');
        } else if (!nameRegex.test(first)) {
            fail(fields.first, 'First name may only contain letters, spaces, apostrophes, periods and hyphens.');
        }

        // Last name
        if (last === '') {
            fail(fields.last, 'Last name is required.');
        } else if (!nameRegex.test(last)) {
            fail(fields.last, 'Last name may only contain letters, spaces, apostrophes, periods and hyphens.');
        }

        // Mobile number
        if (number === '') {
            fail(fields.number, 'Mobile number is required.');
        } else if (!mobileRegex.test(number)) {
            fail(fields.number, 'Mobile number must be 09XXXXXXXXX or +639XXXXXXXXX.');
        }

        // Email
        if (email === '') {
            fail(fields.email, 'Email address is required.');
        } else if (!emailRegex.test(email)) {
            fail(fields.email, 'Please enter a valid email address.');
        }

        // Password
        if (password === '') {
            fail(fields.password, 'Password is required.');
        } else {
            var missing = [];
            if (!passwordRules.length(password)) { missing.push('at least 8 characters'); }
            if (!passwordRules.lower(password)) { missing.push('a lowercase letter'); }
            if (!passwordRules.upper(password)) { missing.push('an uppercase letter'); }
            if (!passwordRules.underscore(password)) { missing.push('an underscore ( _ )'); }
            if (!passwordRules.number(password)) { missing.push('a number'); }

            if (missing.length) {
                fail(fields.password, 'Password needs ' + missing.join(', ') + '.');
            }
        }

        // Confirm password
        if (confirm === '') {
            fail(fields.confirm, 'Please confirm your password.');
        } else if (confirm !== password) {
            fail(fields.confirm, 'Passwords do not match.');
        }

        // Mark every field that failed
        Object.keys(fields).forEach(function (key) {
            fields[key].classList.toggle('is-invalid', invalid.indexOf(fields[key]) !== -1);
        });

        if (errors.length) {
            e.preventDefault();
            openModal(errors, invalid[0]);
        }
        // No errors: the form submits normally to Flask, which checks everything again
    });

    // If Flask sent errors back, the popup is already open: focus it and remember the first bad field
    if (modal.classList.contains('open')) {
        lastFocused = document.querySelector('.input.is-invalid');
        modal.querySelector('.btn-modal').focus();
    }
})();
