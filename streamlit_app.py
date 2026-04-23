import streamlit as st

from risks.risk0102_case import render as render_r1


def require_password():
    if st.session_state.get("authenticated", False):
        return True

    st.title("🔒 Protected App")
    password = st.text_input("Enter password", type="password")

    if password:
        if password == st.secrets["auth"]["password"]:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Incorrect password ❌")

    st.stop()


require_password()

st.set_page_config(page_title="OWASP LLM Security Demo", layout="wide")
st.title("Security Homework – OWASP LLM01 + LLM02 Risks")

render_r1()