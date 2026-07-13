const passwordInput = document.getElementById("passwordInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const result = document.getElementById("result");
const suggestions = document.getElementById("suggestions");
const themeToggle = document.getElementById("themeToggle");
const togglePassword = document.getElementById("togglePassword");
const copyPassword = document.getElementById("copyPassword");
const generatePassword = document.getElementById("generatePassword");
const reqLength = document.getElementById("reqLength");
const reqUpper = document.getElementById("reqUpper");
const reqLower = document.getElementById("reqLower");
const reqNumber = document.getElementById("reqNumber");
const reqSpecial = document.getElementById("reqSpecial");
const strengthLevel = document.getElementById("strengthLevel");
const strengthPercent = document.getElementById("strengthPercent");
const strengthText = document.getElementById("strengthText");

const commonPasswords = [
  "password",
  "123456",
  "qwerty",
  "admin",
  "password123"
];

themeToggle.addEventListener("click", function () {
    document.body.classList.toggle("light-mode");

    if (document.body.classList.contains("light-mode")) {
        themeToggle.textContent = "Dark Mode";
    } else {
        themeToggle.textContent = "Light Mode";
    }
});

passwordInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
        analyzeBtn.click();
    }
});

togglePassword.addEventListener("click", function () {
    const icon = togglePassword.querySelector("i");

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    } else {
        passwordInput.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
});

copyPassword.addEventListener("click", function () {
    if (passwordInput.value.length === 0) {
        return;
    }

    navigator.clipboard.writeText(passwordInput.value);

    copyPassword.textContent = "✅";

    setTimeout(() => {
        copyPassword.textContent = "📋";
    }, 1500);
});

passwordInput.addEventListener("input", function () {
    analyzeBtn.click();
});

generatePassword.addEventListener("click", function () {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "abcdefghijklmnopqrstuvwxyz" +
        "0123456789" +
        "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let password = "";

    for (let i = 0; i < 16; i++) {
        const randomIndex =
            Math.floor(Math.random() * chars.length);

        password += chars[randomIndex];
    }

    passwordInput.value = password;
    analyzeBtn.click();
});

analyzeBtn.addEventListener("click", function () {

    const password = passwordInput.value;

    result.style.display = "block";

    if (commonPasswords.includes(password.toLowerCase())) {
    result.innerHTML = `
        ⚠️ This password is found in common password lists and is extremely insecure.
    `;

    suggestions.innerHTML = `
        <strong>Suggestions:</strong>
        <ul>
            <li>Choose a completely different password.</li>
            <li>Use at least 12 characters.</li>
            <li>Include uppercase, numbers, and symbols.</li>
        </ul>
    `;

    return;
    }

    if (password.length === 0) {
        result.innerHTML = "Please enter a password.";

        strengthLevel.style.height = "0%";
        strengthLevel.style.background = "#1e293b";

        strengthPercent.textContent = "0%";
        strengthText.textContent = "Very Weak";

        suggestions.innerHTML = "";

        return;
    }

    let score = 0;
    let tips = [];

    if (password.length >= 8) {score++;}

    else {tips.push("Use at least 8 characters.");}

    if (/[A-Z]/.test(password)) {score++;}

    else {tips.push("Add uppercase letters.");}

    if (/[a-z]/.test(password)) {score++;}

    else {tips.push("Add lowercase letters.");}

    if (/[0-9]/.test(password)) {score++;}

    else {tips.push("Add numbers.");}

    if (/[^A-Za-z0-9]/.test(password)) {score++;}

    else {tips.push("Add special characters.");}

    let strength = "";

    if (score <= 1) {strength = "Very Weak";}
    
    else if (score === 2) {strength = "Weak";}

    else if (score === 3) {strength = "Medium";}
    
    else if (score === 4) {strength = "Strong";}
    
    else {strength = "Very Strong";}

    const percentage = (score / 5) * 100;
        strengthLevel.style.height = percentage + "%";
        strengthPercent.textContent = Math.round(percentage) + "%";
        strengthText.textContent = strength;

        if (score === 1) {strengthLevel.style.background = "#ef4444";}

        else if (score === 2) {strengthLevel.style.background = "#f97316";}

        else if (score === 3) {strengthLevel.style.background = "#eab308";}

        else if (score === 4) {strengthLevel.style.background = "#3b82f6";}

        else {strengthLevel.style.background = "#22c55e";}

    let charsetSize = 0;

    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^A-Za-z0-9]/.test(password)) charsetSize += 33;

    let combinations = Math.pow(charsetSize, password.length);

    // Rough offline attack speed assumption: 1 billion guesses per second
    let secondsToCrack = combinations / 1000000000;

    const lowerPassword = password.toLowerCase();

    if (lowerPassword.includes("password")) {
        secondsToCrack /= 100000;
        tips.push("Avoid using the word 'password'.");
    }

    if (lowerPassword.includes("admin")) {
        secondsToCrack /= 100000;
        tips.push("Avoid using common words like 'admin'.");
    }

    if (lowerPassword.includes("qwerty")) {
        secondsToCrack /= 100000;
        tips.push("Avoid keyboard patterns like 'qwerty'.");
    }

    if (/123|1234|12345|123456/.test(lowerPassword)) {
        secondsToCrack /= 10000;
        tips.push("Avoid number sequences like 123456.");
    }

    if (/(.)\1{2,}/.test(password)) {
        secondsToCrack /= 10000;
        tips.push("Avoid repeated characters like aaa or 111.");
    }

    secondsToCrack = Math.max(secondsToCrack, 1);

    let entropy =
    password.length *
    Math.log2(charsetSize);

    let crackTime = formatCrackTime(secondsToCrack);

    if (tips.length > 0) {
        suggestions.innerHTML =
            "<strong>Suggestions:</strong><ul>" +
        tips.map(tip => `<li>${tip}</li>`).join("") +
        "</ul>";
    } 
    else {
        suggestions.innerHTML =
            "✓ Excellent password structure.";
    }

    result.innerHTML = `
        Password Score: ${score}/5 <br>
        Strength: ${strength} <br>
        Entropy: ${entropy.toFixed(2)} bits <br>
        Estimated Crack Time: ${crackTime}
    `;

});

passwordInput.addEventListener("input", function () {
    updateRequirements(passwordInput.value);
});

function formatCrackTime(seconds) {

    if (!isFinite(seconds) || seconds <= 0) {
        return "Instantly";
    }

    if (seconds < 1) {
        return "Instantly";
    }

    if (seconds < 60) {
        return Math.round(seconds) + " seconds";
    }

    let minutes = seconds / 60;
    if (minutes < 60) {
        return Math.round(minutes) + " minutes";
    }

    let hours = minutes / 60;
    if (hours < 24) {
        return Math.round(hours) + " hours";
    }

    let days = hours / 24;
    if (days < 365) {
        return Math.round(days) + " days";
    }

    let years = days / 365;
    if (years < 1000) {
        return Math.round(years) + " years";
    }

    if (years < 1000000) {
        return Math.round(years / 1000) + " thousand years";
    }

    if (years < 1000000000) {
        return Math.round(years / 1000000) + " million years";
    }

    return "billions of years";
}

function updateRequirements(password){

    if(password.length >= 8){
        reqLength.innerHTML = "✅ At least 8 characters";
        reqLength.className = "valid";
    } else {
        reqLength.innerHTML = "❌ At least 8 characters";
        reqLength.className = "invalid";
    }

    if(/[A-Z]/.test(password)){
        reqUpper.innerHTML = "✅ One uppercase letter";
        reqUpper.className = "valid";
    } else {
        reqUpper.innerHTML = "❌ One uppercase letter";
        reqUpper.className = "invalid";
    }

    if(/[a-z]/.test(password)){
        reqLower.innerHTML = "✅ One lowercase letter";
        reqLower.className = "valid";
    } else {
        reqLower.innerHTML = "❌ One lowercase letter";
        reqLower.className = "invalid";
    }

    if(/[0-9]/.test(password)){
        reqNumber.innerHTML = "✅ One number";
        reqNumber.className = "valid";
    } else {
        reqNumber.innerHTML = "❌ One number";
        reqNumber.className = "invalid";
    }

    if(/[^A-Za-z0-9]/.test(password)){
        reqSpecial.innerHTML = "✅ One special character";
        reqSpecial.className = "valid";
    } else {
        reqSpecial.innerHTML = "❌ One special character";
        reqSpecial.className = "invalid";
    }
}