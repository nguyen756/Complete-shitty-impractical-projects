import streamlit as st
import bcrypt
import time

st.set_page_config(page_title="Bcrypt Live Demo", layout="wide")

st.title("Bcrypt: The Time-Travel Algorithm")
st.markdown("Experiment with the **Cost Factor** to see how it impacts generation and verification time.")
st.markdown("---")
col1, col2 = st.columns(2)
with col1:
    st.header("1. Generate Hash")
    st.info("See how increasing the slider slows down the CPU.")
    raw_password = st.text_input("Enter a Password", value="student123", key="gen_pass")
    cost = st.slider("Cost Factor (Loops)", min_value=4, max_value=16, value=10)
    iterations = 2 ** cost
    st.caption(f"Math: 2^{cost} = **{iterations:,} iterations**")
    if st.button("Generate Hash"):
        with st.spinner("Hashing... (Wait for it)"):
            start_time = time.time()
            salt = bcrypt.gensalt(rounds=cost)
            hashed_pw = bcrypt.hashpw(raw_password.encode(), salt)
            end_time = time.time()
            duration = end_time - start_time
        st.success("Hash Generated!")
        st.code(hashed_pw.decode('utf-8'), language="text")
        st.metric(label="Time Taken", value=f"{duration:.4f} seconds")
with col2:
    st.header("2. Verify / Crack")
    st.info("Paste the hash from the left to verify it.")
    hash_input = st.text_input("Paste Hash Here", key="hash_input")
    check_password = st.text_input("Enter Password to Check", value="student123", key="check_pass")
    if st.button("Verify Password"):
        if not hash_input:
            st.error("Please paste a hash first!")
        else:
            try:
                target_hash = hash_input.encode()
                
                with st.spinner("Checking... (This also takes time!)"):
                    start_time = time.time()
                    is_match = bcrypt.checkpw(check_password.encode(), target_hash)
                    
                    end_time = time.time()
                    duration = end_time - start_time
                if is_match:
                    st.success("Password is Correct.")
                else:
                    st.error("WRONG PASSWORD.")
                
                st.metric(label="Verification Time", value=f"{duration:.4f} seconds")
            except ValueError:
                st.error("Invalid Hash Format.")