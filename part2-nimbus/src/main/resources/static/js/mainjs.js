$(document).ready(function () {

    // ===== Trang profile: hien thi thong tin nguoi dung dang nhap thanh cong =====
    if ($('#profile').length) {
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            beforeSend: function (xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function (data) {
                // .text() (khong phai .html()) de tranh XSS tu du lieu nguoi dung
                $('#profile').text(data.fullName);
                if (data.images) {
                    $('#images').attr('src', data.images);
                }
            },
            error: function () {
                localStorage.removeItem('token');
                alert('Sorry, you are not logged in.');
                window.location.href = '/login';
            }
        });
    }

    // ===== Ham Login =====
    $('#Login').click(function () {
        var email = document.getElementById('email').value;
        var password = document.getElementById('password').value;
        var basicInfo = JSON.stringify({
            email: email,
            password: password
        });
        $.ajax({
            type: 'POST',
            url: '/auth/login',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: basicInfo,
            success: function (data) {
                localStorage.token = data.token;
                window.location.href = '/user/profile';
            },
            error: function () {
                alert('Login Failed');
            }
        });
    });

    // ===== Ham dang xuat =====
    $('#logout').click(function () {
        localStorage.clear();
        window.location.href = '/login';
    });
});
