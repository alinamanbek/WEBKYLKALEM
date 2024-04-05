from django import forms

class PasswordResetForm(forms.Form):
    # Define your form fields here
    email = forms.EmailField(label='Email')
    # Add more fields as needed
