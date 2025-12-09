import streamlit as st
import bcrypt
import time
import pandas as pd
import re

st.set_page_config(page_title="Bcrypt Lab", layout="wide")

st.title("Bcrypt")
st.markdown("""
<style>
    .anatomy-box { padding: 10px; border-radius: 5px; margin: 5px; text-align: center; color: white; font-weight: bold;}
    .a-prefix { background-color: #FF4B4B; }
    .a-cost { background-color: #FFA500; }
    .a-salt { background-color: #1E90FF; }
    .a-hash { background-color: #2E8B57; }
</style>
""", unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(["Generator", "Verification", "Cost vs Time Graph", "Rainbow Table Attack"])

with tab1:
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Configuration")
        raw_password = st.text_input("Enter a Password", value="example6767", key="gen_pass")
        cost = st.slider("Cost Factor", min_value=1, max_value=20, value=12)
        iterations = 2 ** cost
        st.caption(f"Math: 2^{cost} = **{iterations:,} iterations**")        
        
        # Added key="use_fixed_salt" so Tab 4 can see this setting
        use_fixed_salt = st.checkbox("Enable Fixed Salt", key="use_fixed_salt")
        final_salt = None
        if use_fixed_salt:
            if 'custom_salt_val' not in st.session_state:
                st.session_state.custom_salt_val = bcrypt.gensalt(rounds=cost).decode()
            salt_input = st.text_input("edit salt", value=st.session_state.custom_salt_val)
            st.session_state.custom_salt_val = salt_input
            
            if st.button("Generate New Salt"):
                st.session_state.custom_salt_val = bcrypt.gensalt(rounds=cost).decode()
                st.rerun()
                
            try:
                final_salt = salt_input.encode()
            except:
                final_salt = None
        else:
            final_salt = None

        if st.button("Generate Hash", type="primary"):
            with st.spinner("..."):
                try:
                    start_time = time.time()
                    
                    if not use_fixed_salt:
                        final_salt = bcrypt.gensalt(rounds=cost)
                    hashed_pw = bcrypt.hashpw(raw_password.encode(), final_salt)
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    st.session_state.last_hash = hashed_pw.decode('utf-8')
                    st.session_state.last_time = duration
                    st.rerun()
                except ValueError as e:
                    st.error(f"Error: {e}. Check your fixed salt format.")
                except Exception as e:
                    st.error(f"An error occurred: {e}")

    with col2:
        st.subheader("Result")
        if 'last_hash' in st.session_state:
            full_hash = st.session_state.last_hash
            duration = st.session_state.last_time
            
            st.success("Hash generated")
            st.metric("Time taken", f"{duration:.4f} seconds")
            st.code(full_hash, language="text")
            try:
                parts = full_hash.split('$')                
                prefix = f"${parts[1]}$"
                cost_str = f"{parts[2]}$"
                remainder = parts[3]
                real_salt = remainder[:22]
                real_hash = remainder[22:]
                c1, c2, c3, c4 = st.columns([1, 1, 3, 4])
                with c1:
                    st.markdown(f'<div class="anatomy-box a-prefix">{prefix}</div>', unsafe_allow_html=True)
                    st.caption("Algorithm")
                with c2:
                    st.markdown(f'<div class="anatomy-box a-cost">{cost_str}</div>', unsafe_allow_html=True)
                    st.caption("Cost")
                with c3:
                    st.markdown(f'<div class="anatomy-box a-salt">{real_salt}</div>', unsafe_allow_html=True)
                    st.caption("Salt (22 chars)")
                with c4:
                    st.markdown(f'<div class="anatomy-box a-hash">{real_hash}</div>', unsafe_allow_html=True)
                    st.caption("Ciphertext")
                
                st.info("""
                * **Algorithm:** Usually $2b$.
                * **Cost:** 2^iterations.
                * **Salt:** Random data stored plainly in the string so the system knows how to verify it later.
                * **Ciphertext:** The actual result.
                """)
            except Exception as e:
                st.error(f"Could not parse anatomy: {e}")

with tab2:
    st.header("Verify")
    st.info("Paste the hash and enter the password to verify it.")
    
    hash_input = st.text_input("Paste hash here", key="hash_input")
    check_password = st.text_input("Enter password here", value="example6767", key="check_pass") 
    if st.button("Verify Password"):
        if not hash_input:
            st.error("Please paste a hash first!")
        else:
            try:
                target_hash = hash_input.strip().encode()               
                with st.spinner("Calculating..."):
                    start_time = time.time()
                    is_match = bcrypt.checkpw(check_password.encode(), target_hash)
                    end_time = time.time()
                    duration = end_time - start_time
                
                if is_match:
                    st.balloons()
                    st.success(f"Password is Correct. Verified in {duration:.4f}s")
                else:
                    st.error(f"INCORRECT. Checked in {duration:.4f}s")
                    
            except ValueError:
                st.error("Invalid Hash Format.")

with tab3:
    st.header("The Cost Factor and Time Taken")
    cost_range = st.slider("Select Cost Range", 0, 20, (8, 15))
    
    if st.button("Run"):
        results = []
        progress_bar = st.progress(0)
        test_costs = range(cost_range[0], cost_range[1] + 1)
        
        total_steps = len(test_costs)
        
        for i, c in enumerate(test_costs):
            start = time.time()
            bcrypt.hashpw(b"benchmark", bcrypt.gensalt(rounds=c))
            end = time.time()
            duration = end - start
            results.append({"Cost Factor": c, "Time (s)": duration})
            progress_bar.progress((i + 1) / total_steps)
            
        df = pd.DataFrame(results)
        st.line_chart(df, x="Cost Factor", y="Time (s)")
        st.dataframe(df, width='stretch')
        st.caption("Almost double the time for each +1 in cost factor")

with tab4:
    
    st.header("Rainbow Table Attack")
    leaked_salt_str = "$2b$10$FixedSaltForDemo12345." 
    leaked_salt = leaked_salt_str.encode()
    st.error(f"Leaked salt {leaked_salt_str}")
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Stolen Database")
        try:
            h_alice = bcrypt.hashpw(b"password", leaked_salt).decode()
            h_bob = bcrypt.hashpw(b"123456", leaked_salt).decode()
            h_charlie = bcrypt.hashpw(b"welcome", leaked_salt).decode()
            stolen_db = pd.DataFrame({
                "User": ["Alice", "Bob", "Charlie"],
                "Hash": [h_alice, h_bob, h_charlie]
            })
            st.dataframe(stolen_db, width='stretch')
        except Exception as e:
            st.error(f"Error generating demo: {e}")

    with col_right:
        st.subheader("The Attack")
        common_passwords = ["123456", "password", "admin", "welcome", "qwerty"]
        st.write(f"Dictionary: {common_passwords}")
        
        if st.button("Build Rainbow Table & Crack"):
            with st.spinner("Generating Rainbow Table from Dictionary..."):
                rainbow_data = []
                rainbow_table_map = {}
                for p in common_passwords:
                    h = bcrypt.hashpw(p.encode(), leaked_salt).decode()
                    rainbow_table_map[h] = p
                    rainbow_data.append({"Password Candidate": p, "Computed Hash": h})

                st.markdown("Generated Rainbow Table")
                st.dataframe(pd.DataFrame(rainbow_data), use_container_width=True)
                stolen_db["Recovered Password"] = stolen_db["Hash"].map(rainbow_table_map)
                stolen_db["Status"] = stolen_db["Recovered Password"].apply(lambda x: "CRACKED" if pd.notna(x) else "SAFE")
            
            st.markdown("Final Result")
            st.dataframe(stolen_db, width='stretch')


