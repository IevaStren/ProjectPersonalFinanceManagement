// Show new expense input row
function showNewRow() {
  document.getElementById("new-expense-row").classList.remove("d-none");
}

// Hide new expense row
function cancelNewRow() {
  document.getElementById("new-expense-row").classList.add("d-none");
}

// Enable editing for an existing row
function enableEdit(rowId) {
  document.querySelectorAll(`#row-${rowId} input, #row-${rowId} select`)
    .forEach(el => el.removeAttribute("disabled"));

  document.getElementById(`save-${rowId}`).classList.remove("d-none");
  document.getElementById(`edit-${rowId}`).classList.add("d-none");
}

// Delete expense 
function deleteExpense(expenseId) {
  if (!confirm("Delete expense?")) return;

  fetch(`/expenses/${expenseId}/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  }).then(res => {
    if (res.ok) {
      window.location.reload();
    }
  });
}
