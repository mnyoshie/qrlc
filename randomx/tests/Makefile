$(target).bin : $(target).cpp ../librandomx.a
	$(CXX) $< $(CXXFLAGS) -o $@

run: $(target).bin
	time ./$(target).bin

clean:
	rm $(target).bin
