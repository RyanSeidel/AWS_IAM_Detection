// Show the order total before the customer clicks Buy.
const form = document.querySelector("#order-form");
const total = document.querySelector("#order-total");

function updateTotal() {
  const option = form.sku.selectedOptions[0];
  const price = option ? parseFloat(option.dataset.price) : 0;
  const qty = parseInt(form.qty.value, 10) || 0;
  total.textContent = "Total: $" + (price * qty).toFixed(2);
}

form.addEventListener("input", updateTotal);
updateTotal();
