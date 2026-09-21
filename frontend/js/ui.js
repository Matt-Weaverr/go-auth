const loader = document.querySelector('.loader');
const noticationBox = document.querySelector('.notification-box');
const modalContainer = document.querySelector('.modal-container');
const modalcontent = document.querySelector('.modal-content');
const modalloader = document.querySelector('.loader-modal');

export function displayLoader(show) {
    if (show) {
        loader.style.display = 'flex';
    } else {
        loader.style.display = 'none';
    }
}

let noficationcount = 0;
export function displayNotification(message, error = false) {
    if (error) {
        noticationBox.insertAdjacentHTML('afterbegin', `<div class="notification error" id="notification-${noficationcount}"><p>Error: ${message}</p></div>`);
    } else {
        noticationBox.insertAdjacentHTML('afterbegin', `<div class="notification success" id="notification-${noficationcount}"><p>Success: ${message}</p></div>`);
    }

    let notifid = noficationcount;

    setTimeout(() => {
        const notification = document.getElementById(`notification-${notifid}`);
        if (notification) {
            notification.remove();
        }
    }, 5000);
    noficationcount++;
}

export function displayModal(show, content) {
    modalContainer.style.display = show ? 'flex' : 'none';
    modalcontent.innerHTML = content;
}

export function displayModalLoader(show) {
    if (show) {
        modalloader.style.display = 'flex';
    } else {
        modalloader.style.display = 'none';
    }
}