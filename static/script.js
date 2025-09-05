// Enhanced countdown timer with color changes and blinking
let countdown = 30; // Restore original value
const timerElement = document.getElementById("timer");

let interval = setInterval(() => {
    countdown--;
    timerElement.textContent = `⏱ Time left: ${countdown}s`;
    
    // Add warning color at 10 seconds
    if (countdown <= 10) {
        timerElement.classList.add('timer-warning');
    }
    
    // Add danger color and blinking effect at 5 seconds
    if (countdown <= 5) {
        timerElement.classList.remove('timer-warning');
        timerElement.classList.add('timer-danger');
        timerElement.classList.add('timer-blink');
    }
    
    if (countdown <= 0) {
        clearInterval(interval);
        document.getElementById("login-form").style.display = "none";
        document.getElementById("timeout-msg").style.display = "block";
    }
}, 1000);
