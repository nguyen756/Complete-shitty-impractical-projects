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

tab1, tab2, tab3, tab4 = st.tabs(["Generator", "Verification", "Cost vs Time", "Attack Simulation"])

with tab1:
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Configuration")
        
        raw_password = st.text_input("Enter a Password", value="example6767", key="gen_pass")
        pass_len = len(raw_password.encode('utf-8'))
        
        if pass_len > 72:
            st.warning(f"Password is {pass_len} bytes. Bcrypt truncates at 72 bytes.")
        else:
            st.caption(f"Length: {pass_len}/72 bytes")
        cost = st.slider("Cost Factor", min_value=1, max_value=20, value=12)
        iterations = 2 ** cost
        st.caption(f"Math: 2^{cost} = {iterations:,} iterations")            
        use_fixed_salt = st.checkbox("Enable Fixed Salt", key="use_fixed_salt")
        if 'custom_salt_val' not in st.session_state:
            st.session_state.custom_salt_val = bcrypt.gensalt(rounds=cost).decode()
        final_salt = None
        if use_fixed_salt:
            salt_input = st.text_input("Current Salt", value=st.session_state.custom_salt_val)
            st.session_state.custom_salt_val = salt_input
            if st.button("Roll New Random Salt"):
                st.session_state.custom_salt_val = bcrypt.gensalt(rounds=cost).decode()
                st.rerun()  
            try:
                final_salt = salt_input.encode()
            except:
                st.error("Invalid salt format.")
                final_salt = None
        else:
            final_salt = None
        if st.button("Generate Hash", type="primary"):
            with st.spinner("Hashing..."):
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
                    st.error(f"Error: {e}")
                except Exception as e:
                    st.error(f"An error occurred: {e}")

    with col2:
        st.subheader("Result")
        if 'last_hash' in st.session_state:
            full_hash = st.session_state.last_hash
            duration = st.session_state.last_time           
            st.success("Hash generated successfully")
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
                    st.caption("Alg")
                with c2:
                    st.markdown(f'<div class="anatomy-box a-cost">{cost_str}</div>', unsafe_allow_html=True)
                    st.caption("Cost")
                with c3:
                    st.markdown(f'<div class="anatomy-box a-salt">{real_salt}</div>', unsafe_allow_html=True)
                    st.caption("Salt")
                with c4:
                    st.markdown(f'<div class="anatomy-box a-hash">{real_hash}</div>', unsafe_allow_html=True)
                    st.caption("Ciphertext")
            except Exception:
                st.warning("Could not parse hash anatomy.")
with tab2:
    st.header("Verification")
    hash_input = st.text_input("Paste hash here", key="hash_input")
    check_password = st.text_input("Enter password to check", value="example6767", key="check_pass") 
    
    if st.button("Verify Password"):
        if not hash_input:
            st.error("Please paste a hash first!")
        else:
            try:
                target_hash = hash_input.strip().encode()                  
                start_time = time.time()
                is_match = bcrypt.checkpw(check_password.encode(), target_hash)
                end_time = time.time()               
                duration = end_time - start_time
                if is_match:
                    st.success(f"MATCH! Verified in {duration:.4f}s")
                else:
                    st.error(f"INVALID. Verified in {duration:.4f}s")            
            except ValueError:
                st.error("Invalid Hash Format.")

with tab3:
    st.header("Cost Factor Impact")
    cost_range = st.slider("Select Cost Range to Test", 1, 20, (8, 12))
    if st.button("Run Benchmark"):
        results = []
        progress_bar = st.progress(0)
        test_costs = range(cost_range[0], cost_range[1] + 1)
        
        status_text = st.empty()
        
        for i, c in enumerate(test_costs):
            status_text.text(f"Testing Cost {c}...")
            start = time.time()
            bcrypt.hashpw(b"benchmark", bcrypt.gensalt(rounds=c))
            end = time.time()    
            duration = end - start
            results.append({"Cost Factor": c, "Time (s)": duration})
            progress_bar.progress((i + 1) / len(test_costs))     
        status_text.text("Done")
        df = pd.DataFrame(results)
        c_chart, c_data = st.columns([2,1])
        with c_chart:
            st.line_chart(df, x="Cost Factor", y="Time (s)")
        with c_data:
            st.dataframe(df, hide_index=True)
with tab4:
    st.header("Attack on Static Salt") 
    leaked_salt_str = "$2b$10$FixedSaltForDemo12345." 
    leaked_salt = leaked_salt_str.encode()
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("The Stolen Database")
        try:
            h_alice = bcrypt.hashpw(b"password", leaked_salt).decode()
            h_bob = bcrypt.hashpw(b"123456", leaked_salt).decode()
            h_charlie = bcrypt.hashpw(b"welcome", leaked_salt).decode()
            h_dave = bcrypt.hashpw(b"67676767", leaked_salt).decode()   
            stolen_db = pd.DataFrame({
                "User": ["Alice", "Bob", "Charlie", "Dave"],
                "Hash": [h_alice, h_bob, h_charlie, h_dave]
            })
            st.dataframe(stolen_db, width='stretch')
        except Exception as e:
            st.error(f"Error generating demo DB: {e}")
    with col_right:
        st.subheader("The Attack")
        common_passwords = ["123456", "password", "admin", "welcome", "qwerty", "tuiiucheem"]
        st.write("Attacker's Dictionary:", common_passwords)
        if st.button("Run Dictionary Attack", type="primary"):           
            with st.spinner("Cracking"):
                rainbow_map = {}
                rainbow_data = []                
                for p in common_passwords:
                    h = bcrypt.hashpw(p.encode(), leaked_salt).decode()
                    rainbow_map[h] = p
                    rainbow_data.append({"Word": p, "Computed Hash": h})
                
                st.write("Lookup Table Built")
                st.dataframe(pd.DataFrame(rainbow_data), height=150)   
                st.write("Comparing against Stolen DB...")
                stolen_db["Recovered Password"] = stolen_db["Hash"].map(rainbow_map)
                stolen_db["Status"] = stolen_db["Recovered Password"].apply(
                    lambda x: "CRACKED" if pd.notna(x) else "SAFE"
                )
            st.dataframe(stolen_db, width='stretch')

