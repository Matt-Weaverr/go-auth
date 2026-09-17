const loader = document.querySelector('.loader');
const noticationBox = document.querySelector('.notification-box');
const modelContainer = document.querySelector('.model-container');
const modelcontent = document.querySelector('.model-content');
const modelloader = document.querySelector('.loader-model');

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

export function displayModel(show, content) {
    modelContainer.style.display = show ? 'flex' : 'none';
    modelcontent.innerHTML = content;
}

export function displayModelLoader(show) {
    if (show) {
        modelloader.style.display = 'flex';
    } else {
        modelloader.style.display = 'none';
    }
}