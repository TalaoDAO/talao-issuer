$(document).ready(function() {
  $("#in_progress_button").click(function() {
     //$(this).prop("disabled", true);

    try {if (document.forms['form']['checkValidity']()) {
      console.log('valid');
      $(this).html(
        `<span class="spinner-border spinner-border-sm" ></span> In progress...`
      );
    }} catch(error){
      $(this).html(
        `<span class="spinner-border spinner-border-sm" ></span> In progress...`
      );
    }
  });
});